use brynja_crypto_cpu::static_execution::{Authority, Error as CpuError, Kernel};
use brynja_hash_parallel::{
    self as hash, Fips202BitString, ParallelHashError,
    ParallelHashPublicDeclassification as Public,
    execution::{KeccakSession, in_place as api},
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
    let kernel = if cfg!(target_arch = "aarch64") {
        Kernel::ArmKeccak
    } else {
        Kernel::X86Keccak
    };
    let owner = match Authority::new(kernel) {
        Ok(owner) => owner,
        Err(CpuError::MissingTargetFeatures | CpuError::WrongArchitecture)
            if std::env::var_os("BRYNJA_REQUIRE_SCOPED_PARALLEL").is_none() =>
        {
            return Ok(());
        }
        Err(error) => {
            return Err(io::Error::other(format!(
                "required scheduled route: {error:?}"
            )));
        }
    };
    let session = || {
        KeccakSession::from_static(&owner)
            .map_err(|e| io::Error::other(format!("scheduled authority: {e:?}")))
    };
    macro_rules! check {
        ($plan:ident, $workspace:ident, $leaf_workspace:ident, $width:expr, $xof:expr) => {{
            let plan = hash::$plan::new_bits(input, b).map_err(bad)?;
            let mut workspace = api::$workspace::new(session()?).map_err(bad)?;
            let mut worker = api::$leaf_workspace::new(session()?).map_err(bad)?;
            if workspace.report().kernel != kernel || worker.report().kernel != kernel {
                return Err(io::Error::other("scheduled root/leaf changed route"));
            }
            let mut scratch = vec![0xa5; expected.len()];
            let mut output = vec![0xa5; expected.len()];
            workspace
                .with_bits_and_scratch(&plan, custom, &mut scratch, |mut root| {
                    let mut leaf = [0xa5; $width];
                    for index in 0..plan.leaf_count() {
                        root.merge(worker.execute(plan.job(index)?, &mut leaf)?)?;
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
            if output != expected || scratch.iter().any(|b| *b != 0) {
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
                        root.merge(worker.execute(plan.job(index)?, &mut leaf)?)?;
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
            if suffix.iter().chain(&scratch).any(|b| *b != 0) {
                return Err(io::Error::other("scheduled secret not cleared"));
            }
        }};
    }
    match algorithm {
        "parallel128" => check!(
            ParallelHash128Plan,
            ParallelHash128CollectorWorkspace,
            ParallelHash128LeafWorkspace,
            32,
            false
        ),
        "parallel256" => check!(
            ParallelHash256Plan,
            ParallelHash256CollectorWorkspace,
            ParallelHash256LeafWorkspace,
            64,
            false
        ),
        "parallelxof128" => check!(
            ParallelHash128Plan,
            ParallelHash128CollectorWorkspace,
            ParallelHash128LeafWorkspace,
            32,
            true
        ),
        "parallelxof256" => check!(
            ParallelHash256Plan,
            ParallelHash256CollectorWorkspace,
            ParallelHash256LeafWorkspace,
            64,
            true
        ),
        _ => return Err(io::Error::other("unknown scoped scheduled identity")),
    }
    Ok(())
}
