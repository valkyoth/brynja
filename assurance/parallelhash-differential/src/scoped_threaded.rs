use brynja_hash_parallel::{
    self as hash, Fips202BitString, ParallelHashPublicDeclassification as Public,
    hardened_in_place as api,
};
use brynja_hash_parallel_std::{CancellationToken, ParallelHashExecutor};
use std::io;

pub(super) fn check(
    algorithm: &str,
    custom: Fips202BitString<'_>,
    input: Fips202BitString<'_>,
    valid: u8,
    b: usize,
    expected: &[u8],
) -> Result<(), io::Error> {
    // This mode is already mandatory in the execution oracle. Do not multiply
    // identical portable thread campaigns across every CPU selection mode.
    if std::env::args().nth(1).as_deref() != Some("threads-portable") {
        return Ok(());
    }
    let error = |e| io::Error::other(format!("scoped threaded ParallelHash: {e:?}"));
    let executor = ParallelHashExecutor::new(2, 32768).map_err(error)?;
    let cancellation = CancellationToken::new();
    macro_rules! check {
        ($plan:ident, $workspace:ident, $with:ident, $xof:expr) => {{
            let plan =
                hash::$plan::new_bits(input, b).map_err(|e| io::Error::other(format!("{e:?}")))?;
            let mut workspace = api::$workspace::new();
            let mut output = vec![0xa5; expected.len()];
            executor
                .$with(&mut workspace, &plan, custom, &cancellation, |root| {
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
                .map_err(error)?
                .map_err(|e| io::Error::other(format!("{e:?}")))?;
            if output != expected {
                return Err(io::Error::other("scoped threaded public mismatch"));
            }
            output.fill(0xa5);
            let split = if $xof {
                expected.len().saturating_sub(1).min(17)
            } else {
                0
            };
            let (prefix, suffix) = output.split_at_mut(split);
            let secret = executor
                .$with(&mut workspace, &plan, custom, &cancellation, |root| {
                    if $xof {
                        let mut reader = root.finalize_xof()?;
                        reader.squeeze_public(prefix, Public::acknowledge())?;
                        reader.squeeze_final_bits_secret(suffix, valid)
                    } else {
                        root.finalize_secret_bits(suffix, valid)
                    }
                })
                .map_err(error)?
                .map_err(|e| io::Error::other(format!("{e:?}")))?;
            if prefix != &expected[..split] || secret.expose() != &expected[split..] {
                return Err(io::Error::other("scoped threaded secret mismatch"));
            }
            drop(secret);
            if suffix.iter().any(|byte| *byte != 0) {
                return Err(io::Error::other("scoped threaded output not cleared"));
            }
        }};
    }
    match algorithm {
        "parallel128" => check!(
            ParallelHash128Plan,
            ParallelHash128CollectorWorkspace,
            with128_bits,
            false
        ),
        "parallel256" => check!(
            ParallelHash256Plan,
            ParallelHash256CollectorWorkspace,
            with256_bits,
            false
        ),
        "parallelxof128" => check!(
            ParallelHash128Plan,
            ParallelHash128CollectorWorkspace,
            with128_bits,
            true
        ),
        "parallelxof256" => check!(
            ParallelHash256Plan,
            ParallelHash256CollectorWorkspace,
            with256_bits,
            true
        ),
        _ => return Err(io::Error::other("unknown scoped threaded identity")),
    }
    Ok(())
}
