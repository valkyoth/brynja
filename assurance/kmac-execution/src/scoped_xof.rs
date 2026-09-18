use crate::{lifecycle::Case, selection::Selection};
use brynja_mac_kmac::{
    Fips202BitString, KmacError, KmacPublicDeclassification,
    execution::{Mode, in_place as api},
};
use std::io;
fn invalid(e: impl core::fmt::Debug) -> io::Error {
    io::Error::other(format!("scoped KMACXOF: {e:?}"))
}
fn public() -> KmacPublicDeclassification {
    KmacPublicDeclassification::acknowledge()
}

pub fn check(case: Case<'_>, selection: &Selection) -> Result<(), io::Error> {
    if !matches!(case.algorithm, "kmacxof128" | "kmacxof256") {
        return Ok(());
    }
    let session = match selection.mode()? {
        Mode::Require(Some(s)) | Mode::Prefer(Some(s)) => s,
        Mode::Portable | Mode::Prefer(None) => return Ok(()),
        Mode::Require(None) => return Err(invalid("missing required session")),
    };
    macro_rules! campaign {
        ($workspace:ident) => {{
            let mut workspace = api::$workspace::new(session).map_err(invalid)?;
            selection.check_actual(Some(workspace.report()))?;
            let mut output = vec![0xa5; case.expected.len()];
            let mut scratch = vec![0x5a; case.expected.len().saturating_add(11)];
            workspace
                .with_bits_and_scratch_conformance(case.key, case.custom, &mut scratch, |state| {
                    state
                        .finalize_bits_xof_conformance(case.message)?
                        .squeeze_final_bits_public(&mut output, case.valid, public())
                })
                .map_err(invalid)?
                .map_err(invalid)?;
            if output != case.expected || scratch.iter().any(|b| *b != 0) {
                return Err(invalid("public output/staging mismatch"));
            }
            output.fill(0xa5);
            let secret = workspace
                .with_bits_conformance(case.key, case.custom, |state| {
                    state
                        .finalize_bits_xof_conformance(case.message)?
                        .squeeze_final_bits_secret(&mut output, case.valid)
                })
                .map_err(invalid)?
                .map_err(invalid)?;
            if secret.expose() != case.expected {
                return Err(invalid("secret mismatch"));
            }
            drop(secret);
            if output.iter().any(|b| *b != 0) {
                return Err(invalid("secret Drop cleanup"));
            }
            output.fill(0xa5);
            workspace
                .with_bits_conformance(case.key, case.custom, |mut state| {
                    let bytes = case.message.as_bytes();
                    let split = if case.message.is_byte_aligned() {
                        bytes.len()
                    } else {
                        bytes
                            .len()
                            .checked_sub(1)
                            .ok_or(KmacError::InvalidBitString)?
                    };
                    for part in bytes
                        .get(..split)
                        .ok_or(KmacError::InvalidBitString)?
                        .chunks(17)
                    {
                        state.update(&[])?;
                        state.update(part)?;
                    }
                    let tail = bytes.get(split..).ok_or(KmacError::InvalidBitString)?;
                    let bits = Fips202BitString::new(
                        tail,
                        if tail.is_empty() {
                            0
                        } else {
                            case.message.valid_bits_in_last_byte()
                        },
                    )
                    .map_err(|_| KmacError::InvalidBitString)?;
                    let mut reader = state.finalize_bits_xof_conformance(bits)?;
                    let last = output.len().saturating_sub(1);
                    let (prefix, tail) = output.split_at_mut(last);
                    let mut secret_turn = true;
                    for part in prefix.chunks_mut(73) {
                        reader.squeeze_public(&mut [], public())?;
                        drop(reader.squeeze_secret(&mut [])?);
                        if secret_turn {
                            let mut staging = vec![0xa5; part.len()];
                            let secret = reader.squeeze_secret(&mut staging)?;
                            // This is test-vector output, explicitly declassified for comparison.
                            part.copy_from_slice(secret.expose());
                            drop(secret);
                            if staging.iter().any(|b| *b != 0) {
                                return Err(KmacError::SecretMemory);
                            }
                        } else {
                            reader.squeeze_public(part, public())?;
                        }
                        secret_turn = !secret_turn;
                    }
                    reader.squeeze_final_bits_public(tail, case.valid, public())
                })
                .map_err(invalid)?
                .map_err(invalid)?;
            if output != case.expected {
                return Err(invalid("mixed streaming mismatch"));
            }
        }};
    }
    match case.algorithm {
        "kmacxof128" => campaign!(KmacXof128Workspace),
        "kmacxof256" => campaign!(KmacXof256Workspace),
        _ => return Err(invalid("unexpected identity")),
    }
    Ok(())
}
