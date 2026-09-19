use brynja_hash_parallel::{
    self as hash, Fips202BitString, ParallelHashError,
    ParallelHashPublicDeclassification as Public, hardened_in_place as api,
};
use std::io;

pub(super) fn check(
    algorithm: &str,
    custom: Fips202BitString<'_>,
    input: Fips202BitString<'_>,
    valid: u8,
    b: usize,
    expected: &[u8],
) -> Result<(), io::Error> {
    let bad = |e| io::Error::other(format!("scoped scheduled ParallelHash: {e:?}"));
    macro_rules! check {
        ($plan:ident, $workspace:ident, $width:expr, $xof:expr) => {{
            let plan = hash::$plan::new_bits(input, b).map_err(bad)?;
            let mut workspace = api::$workspace::new();
            let mut output = vec![0xa5; expected.len()];
            workspace
                .with_bits(&plan, custom, |mut root| {
                    let mut leaf = [0xa5; $width];
                    for index in 0..plan.leaf_count() {
                        root.merge(plan.job(index)?.execute(&mut leaf)?)?;
                        if leaf != [0; $width] {
                            return Err(ParallelHashError::SecretMemory);
                        }
                    }
                    if $xof {
                        root.finalize_xof()?.squeeze_final_bits_public(
                            &mut output,
                            valid,
                            Public::acknowledge(),
                        )
                    } else {
                        root.finalize_public_bits(&mut output, valid, Public::acknowledge())
                    }
                })
                .map_err(bad)?
                .map_err(bad)?;
            if output != expected {
                return Err(io::Error::other("scoped scheduled public mismatch"));
            }
            output.fill(0xa5);
            let split = if $xof {
                expected.len().saturating_sub(1).min(17)
            } else {
                0
            };
            let (prefix, suffix) = output.split_at_mut(split);
            let secret = workspace
                .with_bits(&plan, custom, |mut root| {
                    let mut leaf = [0; $width];
                    for index in 0..plan.leaf_count() {
                        root.merge(plan.job(index)?.execute(&mut leaf)?)?;
                    }
                    if $xof {
                        let mut reader = root.finalize_xof()?;
                        reader.squeeze_public(prefix, Public::acknowledge())?;
                        reader.squeeze_final_bits_secret(suffix, valid)
                    } else {
                        root.finalize_secret_bits(suffix, valid)
                    }
                })
                .map_err(bad)?
                .map_err(bad)?;
            if prefix != &expected[..split] || secret.expose() != &expected[split..] {
                return Err(io::Error::other("scoped scheduled mixed/secret mismatch"));
            }
            drop(secret);
            if suffix.iter().any(|b| *b != 0) {
                return Err(io::Error::other("scheduled secret not cleared"));
            }
        }};
    }
    match algorithm {
        "parallel128" => check!(
            ParallelHash128Plan,
            ParallelHash128CollectorWorkspace,
            32,
            false
        ),
        "parallel256" => check!(
            ParallelHash256Plan,
            ParallelHash256CollectorWorkspace,
            64,
            false
        ),
        "parallelxof128" => check!(
            ParallelHash128Plan,
            ParallelHash128CollectorWorkspace,
            32,
            true
        ),
        "parallelxof256" => check!(
            ParallelHash256Plan,
            ParallelHash256CollectorWorkspace,
            64,
            true
        ),
        _ => return Err(io::Error::other("unknown scoped scheduled identity")),
    }
    Ok(())
}
