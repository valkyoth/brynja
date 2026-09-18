use crate::{bit_string, selection::Selection, valid_bits};
use brynja_hash_tuple::{
    Fips202BitString, TupleHashPublicDeclassification as Public,
    execution::{Mode, in_place as api},
};
use std::io;
fn bad(error: impl core::fmt::Debug) -> io::Error {
    io::Error::other(format!("scoped TupleHash oracle: {error:?}"))
}

pub(super) fn check(
    algorithm: &str,
    custom: Fips202BitString<'_>,
    items: &[(Vec<u8>, usize)],
    output_bits: usize,
    expected: &[u8],
    selection: &Selection,
) -> Result<(), io::Error> {
    if !matches!(algorithm, "tuple128" | "tuple256") {
        return Ok(());
    }
    let session = match selection.mode()? {
        Mode::Require(Some(session)) | Mode::Prefer(Some(session)) => session,
        Mode::Portable | Mode::Prefer(None) => return Ok(()),
        Mode::Require(None) => return Err(bad("missing required session")),
    };
    macro_rules! check {
        ($workspace:ident) => {{
            let mut workspace = api::$workspace::new(session).map_err(bad)?;
            selection.check_actual(Some(workspace.report()))?;
            let mut actual = vec![0xa5; expected.len()];
            let mut scratch = vec![0x55; expected.len().saturating_add(1)];
            workspace
                .with_bits_and_scratch(custom, &mut scratch, |mut state| {
                    for (bytes, count) in items {
                        state
                            .push_item_bits(bit_string(bytes, *count, 0)?)
                            .map_err(bad)?;
                    }
                    state
                        .finalize_public_bits(
                            &mut actual,
                            valid_bits(output_bits),
                            Public::acknowledge(),
                        )
                        .map_err(bad)
                })
                .map_err(bad)??;
            if actual != expected || scratch.iter().any(|byte| *byte != 0) {
                return Err(bad("public output or scratch mismatch"));
            }
            actual.fill(0xa5);
            let secret = workspace
                .with_bits(custom, |mut state| {
                    for (bytes, count) in items {
                        let mut writer = state
                            .begin_item(u128::try_from(*count).map_err(bad)?)
                            .map_err(bad)?;
                        let complete = count / 8;
                        for chunk in bytes
                            .get(..complete)
                            .ok_or_else(|| bad("prefix"))?
                            .chunks(17)
                        {
                            writer.update(chunk).map_err(bad)?;
                        }
                        let tail = count % 8;
                        if tail != 0 {
                            writer
                                .update_bits(bit_string(
                                    bytes.get(complete..).ok_or_else(|| bad("tail"))?,
                                    tail,
                                    0,
                                )?)
                                .map_err(bad)?;
                        }
                        writer.finish().map_err(bad)?;
                    }
                    state
                        .finalize_secret_bits(&mut actual, valid_bits(output_bits))
                        .map_err(bad)
                })
                .map_err(bad)??;
            if secret.expose() != expected {
                return Err(bad("secret output mismatch"));
            }
            drop(secret);
            if actual.iter().any(|byte| *byte != 0) {
                return Err(bad("secret output not cleared"));
            }
            selection.check_actual(Some(workspace.report()))?;
        }};
    }
    match algorithm {
        "tuple128" => check!(TupleHash128Workspace),
        "tuple256" => check!(TupleHash256Workspace),
        _ => return Err(bad("unexpected identity")),
    }
    Ok(())
}
