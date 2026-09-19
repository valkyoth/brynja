use brynja_crypto_cpu::static_execution::{Authority, Error as CpuError, Kernel};
use brynja_hash_parallel::{
    Fips202BitString, ParallelHashError, ParallelHashPublicDeclassification as Public,
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
    let bad = |e| io::Error::other(format!("scoped accelerated ParallelHash: {e:?}"));
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
                "required scoped route: {error:?}"
            )));
        }
    };
    let session = || {
        KeccakSession::from_static(&owner)
            .map_err(|e| io::Error::other(format!("scoped authority: {e:?}")))
    };
    macro_rules! check {
        ($workspace:ident) => {{
            let mut workspace = api::$workspace::new(session()?, session()?).map_err(bad)?;
            if workspace.root_report().kernel != kernel || workspace.leaf_report().kernel != kernel
            {
                return Err(io::Error::other("scoped root/leaf changed route"));
            }
            let mut block = vec![0xa5; b];
            let mut scratch = vec![0xa5; expected.len()];
            let mut output = vec![0xa5; expected.len()];
            workspace
                .with_bits_and_scratch(&mut block, custom, &mut scratch, |state| {
                    state.finalize_bits_public(input, &mut output, valid, Public::acknowledge())
                })
                .map_err(bad)?
                .map_err(bad)?;
            if output != expected || scratch.iter().chain(&block).any(|b| *b != 0) {
                return Err(io::Error::other(
                    "scoped accelerated public output/cleanup mismatch",
                ));
            }
            output.fill(0xa5);
            let secret = workspace
                .with_bits(&mut block, custom, |mut state| {
                    let complete = if input.is_byte_aligned() {
                        input.as_bytes().len()
                    } else {
                        input.as_bytes().len().saturating_sub(1)
                    };
                    for chunk in input.as_bytes()[..complete].chunks(13) {
                        state.update(chunk)?;
                    }
                    let tail = Fips202BitString::new(
                        &input.as_bytes()[complete..],
                        if input.is_byte_aligned() {
                            0
                        } else {
                            input.valid_bits_in_last_byte()
                        },
                    )
                    .map_err(|_| ParallelHashError::InvalidBitString)?;
                    state.finalize_bits_secret(tail, &mut output, valid)
                })
                .map_err(bad)?
                .map_err(bad)?;
            if secret.expose() != expected {
                return Err(io::Error::other(
                    "scoped accelerated secret output mismatch",
                ));
            }
            drop(secret);
            if output.iter().chain(&block).any(|b| *b != 0) {
                return Err(io::Error::other(
                    "scoped accelerated secret cleanup mismatch",
                ));
            }
        }};
    }
    macro_rules! xof {
        ($workspace:ident) => {{
            let mut workspace = api::$workspace::new(session()?, session()?).map_err(bad)?;
            if workspace.root_report().kernel != kernel || workspace.leaf_report().kernel != kernel
            {
                return Err(io::Error::other("scoped XOF changed route"));
            }
            let mut scratch = vec![0xa5; expected.len()];
            let mut block = vec![0xa5; b];
            let mut output = vec![0xa5; expected.len()];
            workspace
                .with_bits_and_scratch(&mut block, custom, &mut scratch, |state| {
                    state.finalize_bits_xof(input)?.squeeze_final_bits_public(
                        &mut output,
                        valid,
                        Public::acknowledge(),
                    )
                })
                .map_err(bad)?
                .map_err(bad)?;
            if output != expected || block.iter().chain(&scratch).any(|byte| *byte != 0) {
                return Err(io::Error::other("scoped XOF public output/block mismatch"));
            }
            output.fill(0xa5);
            let split = expected.len().saturating_sub(1).min(17);
            let (prefix, suffix) = output.split_at_mut(split);
            let secret = workspace
                .with_bits(&mut block, custom, |mut state| {
                    let complete = if input.is_byte_aligned() {
                        input.as_bytes().len()
                    } else {
                        input.as_bytes().len().saturating_sub(1)
                    };
                    for chunk in input.as_bytes()[..complete].chunks(13) {
                        state.update(chunk)?;
                    }
                    let tail = Fips202BitString::new(
                        &input.as_bytes()[complete..],
                        if input.is_byte_aligned() {
                            0
                        } else {
                            input.valid_bits_in_last_byte()
                        },
                    )
                    .map_err(|_| brynja_hash_parallel::ParallelHashError::InvalidBitString)?;
                    let mut reader = state.finalize_bits_xof(tail)?;
                    reader.squeeze_public(prefix, Public::acknowledge())?;
                    reader.squeeze_final_bits_secret(suffix, valid)
                })
                .map_err(bad)?
                .map_err(bad)?;
            if prefix != &expected[..split] || secret.expose() != &expected[split..] {
                return Err(io::Error::other("scoped XOF mixed output mismatch"));
            }
            drop(secret);
            if suffix.iter().chain(&block).any(|byte| *byte != 0) {
                return Err(io::Error::other(
                    "scoped XOF secret output/block not cleared",
                ));
            }
        }};
    }
    match algorithm {
        "parallel128" => check!(ParallelHash128Workspace),
        "parallel256" => check!(ParallelHash256Workspace),
        "parallelxof128" => xof!(ParallelHashXof128Workspace),
        "parallelxof256" => xof!(ParallelHashXof256Workspace),
        _ => return Err(io::Error::other("unknown scoped accelerated identity")),
    }
    Ok(())
}
