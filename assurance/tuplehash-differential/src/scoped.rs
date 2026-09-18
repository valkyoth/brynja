use super::{bit_string, invalid, valid_bits};
use brynja_hash_tuple::{
    Fips202BitString, TupleHashPublicDeclassification, hardened_in_place as api,
};
use std::io;

pub(super) fn check(
    algorithm: &str,
    custom: Fips202BitString<'_>,
    items: &[(Vec<u8>, usize)],
    output_bits: usize,
    expected: &[u8],
    line: usize,
) -> Result<(), io::Error> {
    let valid = valid_bits(output_bits);
    macro_rules! public {
        ($state:ident, $actual:ident, fixed) => {
            $state.finalize_public_bits(
                &mut $actual,
                valid,
                TupleHashPublicDeclassification::acknowledge(),
            )
        };
        ($state:ident, $actual:ident, xof) => {
            $state.finalize_xof().and_then(|mut reader| {
                let split = $actual.len().saturating_sub(1);
                let (prefix, tail) = $actual.split_at_mut(split);
                for chunk in prefix.chunks_mut(17) {
                    reader.squeeze_public(chunk, TupleHashPublicDeclassification::acknowledge())?;
                }
                reader.squeeze_final_bits_public(
                    tail,
                    valid,
                    TupleHashPublicDeclassification::acknowledge(),
                )
            })
        };
    }
    macro_rules! secret {
        ($state:ident, $actual:ident, fixed) => {
            $state.finalize_secret_bits(&mut $actual, valid)
        };
        ($state:ident, $actual:ident, xof) => {
            $state
                .finalize_xof()
                .and_then(|reader| reader.squeeze_final_bits_secret(&mut $actual, valid))
        };
    }
    macro_rules! run {
        ($workspace:ident, $kind:ident) => {{
            let mut workspace = api::$workspace::new();
            let mut actual = vec![0xa5; expected.len()];
            workspace
                .with_bits(custom, |mut state| {
                    for (bytes, count) in items {
                        state
                            .push_item_bits(bit_string(bytes, *count, line)?)
                            .map_err(|_| invalid(line, "scoped item rejected"))?;
                    }
                    public!(state, actual, $kind)
                        .map_err(|_| invalid(line, "scoped public output rejected"))
                })
                .map_err(|_| invalid(line, "scoped setup rejected"))??;
            if actual != expected {
                return Err(invalid(line, "scoped public/oracle mismatch"));
            }
            actual.fill(0xa5);
            let secret = workspace
                .with_bits(custom, |mut state| {
                    for (bytes, count) in items {
                        let mut writer = state
                            .begin_item(
                                u128::try_from(*count)
                                    .map_err(|_| invalid(line, "item length overflow"))?,
                            )
                            .map_err(|_| invalid(line, "scoped writer rejected"))?;
                        let complete = count / 8;
                        for chunk in bytes
                            .get(..complete)
                            .ok_or_else(|| invalid(line, "item prefix shape"))?
                            .chunks(17)
                        {
                            writer
                                .update(&[])
                                .map_err(|_| invalid(line, "empty fragment rejected"))?;
                            writer
                                .update(chunk)
                                .map_err(|_| invalid(line, "scoped byte fragment rejected"))?;
                        }
                        let tail = count % 8;
                        if tail != 0 {
                            writer
                                .update_bits(bit_string(
                                    bytes
                                        .get(complete..)
                                        .ok_or_else(|| invalid(line, "item tail shape"))?,
                                    tail,
                                    line,
                                )?)
                                .map_err(|_| invalid(line, "scoped bit fragment rejected"))?;
                        }
                        writer
                            .finish()
                            .map_err(|_| invalid(line, "scoped item finish rejected"))?;
                    }
                    secret!(state, actual, $kind)
                        .map_err(|_| invalid(line, "scoped secret output rejected"))
                })
                .map_err(|_| invalid(line, "scoped setup rejected"))??;
            if secret.expose() != expected {
                return Err(invalid(line, "scoped secret/oracle mismatch"));
            }
            drop(secret);
            if actual.iter().any(|byte| *byte != 0) {
                return Err(invalid(line, "scoped secret not cleared"));
            }
        }};
    }
    match algorithm {
        "tuple128" => run!(TupleHash128Workspace, fixed),
        "tuple256" => run!(TupleHash256Workspace, fixed),
        "tuplexof128" => run!(TupleHashXof128Workspace, xof),
        "tuplexof256" => run!(TupleHashXof256Workspace, xof),
        _ => return Err(invalid(line, "unrecognized scoped identity")),
    }
    Ok(())
}
