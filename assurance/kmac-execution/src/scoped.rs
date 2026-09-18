use crate::{lifecycle::Case, selection::Selection};
use brynja_mac_kmac::{
    KmacError,
    execution::{Mode, in_place as api},
};
use std::io;

fn invalid(e: impl core::fmt::Debug) -> io::Error {
    io::Error::other(format!("scoped KMAC: {e:?}"))
}

pub fn check(case: Case<'_>, selection: &Selection) -> Result<(), io::Error> {
    if !matches!(case.algorithm, "kmac128" | "kmac256") {
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
            let mut scratch = vec![0x5a; case.expected.len().saturating_add(7)];
            workspace
                .with_bits_and_scratch_conformance(case.key, case.custom, &mut scratch, |state| {
                    state
                        .finalize_tag_bits_conformance(case.message, &mut output, case.valid)
                        .map(|_| ())
                })
                .map_err(invalid)?
                .map_err(invalid)?;
            if output != case.expected || scratch.iter().any(|b| *b != 0) {
                return Err(invalid("tag/staging mismatch"));
            }
            output.fill(0xa5);
            let secret = workspace
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
                    let complete = bytes.get(..split).ok_or(KmacError::InvalidBitString)?;
                    for part in complete.chunks(17) {
                        state.update(&[])?;
                        state.update(part)?;
                    }
                    let tail = bytes.get(split..).ok_or(KmacError::InvalidBitString)?;
                    let tail = brynja_mac_kmac::Fips202BitString::new(
                        tail,
                        if tail.is_empty() {
                            0
                        } else {
                            case.message.valid_bits_in_last_byte()
                        },
                    )
                    .map_err(|_| KmacError::InvalidBitString)?;
                    state.finalize_secret_bits_conformance(tail, &mut output, case.valid)
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
            let candidate = brynja_mac_kmac::Fips202BitString::new(case.expected, case.valid)
                .map_err(invalid)?;
            let verified = workspace
                .with_bits_conformance(case.key, case.custom, |state| {
                    state.verify_bits_conformance(case.message, candidate)
                })
                .map_err(invalid)?
                .map_err(invalid)?;
            if !verified.expose_public() {
                return Err(invalid("verification mismatch"));
            }
        }};
    }
    match case.algorithm {
        "kmac128" => campaign!(Kmac128Workspace),
        "kmac256" => campaign!(Kmac256Workspace),
        _ => return Err(invalid("unexpected identity")),
    }
    Ok(())
}
