use super::super::{leaf, selection};
use super::*;
use brynja_hash_parallel::{Fips202BitString, Fips202Output, execution::Identity};
fn config(workers: usize, leaves: Preference) -> Config {
    Config {
        workers,
        leaves,
        max_leaves: 64,
        root: Preference::Portable,
        minimum_permutations: 1,
        max_group_permutations: 128,
    }
}
fn request(
    identity: Identity,
    input: &[u8],
    valid: u8,
    block_size: usize,
) -> Result<Request<'_>, Error> {
    Ok(Request {
        identity,
        input: Fips202BitString::new(input, valid).map_err(|_| Error::Limits)?,
        block_size,
        customization: Fips202BitString::new(&[19], 5).map_err(|_| Error::Limits)?,
    })
}
fn reference(request: &Request<'_>, out: &mut [u8]) -> Result<(), Error> {
    let mut workspace = vec![0; request.block_size];
    let output = Fips202Output::new(out, 5).map_err(|_| Error::Limits)?;
    macro_rules! fixed {
        ($ty:ty) => {
            <$ty>::new_bits(&mut workspace, request.customization)
                .map_err(|e| Error::from(brynja_hash_parallel::execution::Error::from(e)))?
                .finalize_bits(request.input, output)
                .map_err(|e| Error::from(brynja_hash_parallel::execution::Error::from(e)))?
        };
    }
    macro_rules! xof {
        ($ty:ty) => {
            <$ty>::new_bits(&mut workspace, request.customization)
                .map_err(|e| Error::from(brynja_hash_parallel::execution::Error::from(e)))?
                .finalize_bits_xof(request.input)
                .map_err(|e| Error::from(brynja_hash_parallel::execution::Error::from(e)))?
                .squeeze_final_bits(output)
                .map_err(|e| Error::from(brynja_hash_parallel::execution::Error::from(e)))?
        };
    }
    match request.identity {
        Identity::ParallelHash128 => fixed!(brynja_hash_parallel::ParallelHash128<'_>),
        Identity::ParallelHash256 => fixed!(brynja_hash_parallel::ParallelHash256<'_>),
        Identity::ParallelHashXof128 => xof!(brynja_hash_parallel::ParallelHashXof128<'_>),
        Identity::ParallelHashXof256 => xof!(brynja_hash_parallel::ParallelHashXof256<'_>),
    }
    Ok(())
}
fn campaign(preference: Preference) -> Result<(), Error> {
    let selected = selection::Selection::new(preference)?;
    let engine = selected.executor(1)?;
    let kernel = engine
        .kernel()
        .map_err(|e| Error::Batch(leaf::Error::Hash(e)))?;
    if preference != Preference::Portable
        && std::env::var_os("BRYNJA_REQUIRE_PARALLELHASH_BATCH").is_some()
    {
        assert!(kernel.is_some());
    }
    for identity in [
        Identity::ParallelHash128,
        Identity::ParallelHash256,
        Identity::ParallelHashXof128,
        Identity::ParallelHashXof256,
    ] {
        for block in [1_usize, 7, 136] {
            for length in [
                0,
                1,
                block.saturating_mul(3).saturating_add(1),
                block.saturating_mul(4),
                block.saturating_mul(5).saturating_add(1),
                block.saturating_mul(9),
            ] {
                let mut input: Vec<_> = (0..length)
                    .map(|i| i.to_le_bytes()[0].wrapping_mul(13))
                    .collect();
                if let Some(last) = input.last_mut() {
                    *last &= 0x1f;
                }
                let request = request(identity, &input, if length == 0 { 0 } else { 5 }, block)?;
                let mut expected = [0; 173];
                reference(&request, &mut expected)?;
                let leaves = length.div_ceil(block);
                for workers in [1, 2, 3] {
                    let executor = Executor::new(config(workers, preference))?;
                    let mut out = [0xa5; 173];
                    let mut scratch = [0xff; 180];
                    let token = CancellationToken::new();
                    let report =
                        executor.hash_public_bits(&request, &mut out, 5, &mut scratch, &token)?;
                    assert_eq!(out, expected);
                    assert_eq!(scratch, [0; 180]);
                    assert_eq!(report.execution.leaves, leaves as u128);
                    assert_eq!(report.groups, leaves.div_ceil(4) as u128);
                    assert_eq!(
                        report.execution.thread_width,
                        workers.min(leaves.div_ceil(4))
                    );
                    let accelerated = if let Some(k) = kernel {
                        leaves
                            .checked_div(k.width())
                            .and_then(|n| n.checked_mul(k.width()))
                            .ok_or(Error::Limits)?
                    } else {
                        0
                    };
                    assert_eq!(report.execution.accelerated_leaves, accelerated as u128);
                    assert_eq!(report.vector_calls != 0, accelerated != 0);
                    assert_eq!(report.execution.root, None);
                    let (secret, secret_report) =
                        executor.hash_secret_bits(&request, &mut out, 5, &token)?;
                    assert_eq!(secret.expose(), expected);
                    assert_eq!(secret_report, report);
                    drop(secret);
                    assert_eq!(out, [0; 173]);
                }
            }
        }
    }
    Ok(())
}
#[test]
fn portable_threads_bits_outputs_and_counters() -> Result<(), Error> {
    campaign(Preference::Portable)
}
#[test]
fn preferred_threads_bits_outputs_and_counters() -> Result<(), Error> {
    campaign(Preference::Prefer)
}
#[test]
fn request_rejections_preserve_public_clear_secret_and_allow_reuse() -> Result<(), Error> {
    let request = request(Identity::ParallelHash128, b"abcdefghi", 8, 1)?;
    for kind in 0..5 {
        let mut cfg = config(2, Preference::Portable);
        if kind == 0 {
            cfg.max_group_permutations = 0;
        }
        if kind == 1 {
            cfg.max_leaves = 1;
        }
        let executor = Executor::new(cfg)?;
        let token = CancellationToken::new();
        if kind == 2 {
            token.cancel();
        }
        let mut out = [0xa5; 32];
        let mut scratch = [0xff; 32];
        let _busy = if kind == 3 {
            Some(executor.inner.base.gate()?)
        } else {
            None
        };
        let valid = if kind == 4 { 0 } else { 8 };
        assert!(
            executor
                .hash_public_bits(&request, &mut out, valid, &mut scratch, &token)
                .is_err()
        );
        assert_eq!(out, [0xa5; 32]);
        assert_eq!(scratch, [0; 32]);
        assert!(
            executor
                .hash_secret_bits(&request, &mut out, valid, &token)
                .is_err()
        );
        assert_eq!(out, [0; 32]);
        drop(_busy);
        let empty = request_empty()?;
        drop(executor.hash_secret(&empty, &mut out, &CancellationToken::new())?);
    }
    Ok(())
}
fn request_empty() -> Result<Request<'static>, Error> {
    request(Identity::ParallelHash128, &[], 0, 1)
}
#[test]
fn required_partial_group_rejects_without_output() -> Result<(), Error> {
    let executor = Executor::new(config(2, Preference::RequireStatic))?;
    let request = request(Identity::ParallelHash256, b"abcde", 8, 1)?;
    let mut out = [0xa5; 32];
    let mut scratch = [0xff; 32];
    assert!(
        executor
            .hash_public(&request, &mut out, &mut scratch, &CancellationToken::new())
            .is_err()
    );
    assert_eq!(out, [0xa5; 32]);
    assert_eq!(scratch, [0; 32]);
    Ok(())
}
#[test]
fn empty_input_has_no_workers() -> Result<(), Error> {
    let executor = Executor::new(Config {
        workers: 2,
        max_leaves: 32,
        root: Preference::Portable,
        leaves: Preference::Portable,
        minimum_permutations: 1,
        max_group_permutations: 32,
    })?;
    let request = Request {
        identity: brynja_hash_parallel::execution::Identity::ParallelHash128,
        input: brynja_hash_parallel::Fips202BitString::new(&[], 0).map_err(|_| Error::Limits)?,
        block_size: 8,
        customization: brynja_hash_parallel::Fips202BitString::new(&[], 0)
            .map_err(|_| Error::Limits)?,
    };
    let mut output = [0; 32];
    let (value, report) = executor.hash_secret(&request, &mut output, &CancellationToken::new())?;
    assert_eq!(value.expose().len(), 32);
    assert_eq!(report.execution.thread_width, 0);
    assert_eq!(report.groups, 0);
    Ok(())
}

#[test]
fn scoped_multibuffer_static_and_mixed_routes() -> Result<(), Error> {
    use brynja_crypto_cpu::static_execution::{Error as StaticError, Kernel as RootKernel};

    let kernel = if cfg!(target_arch = "aarch64") {
        leaf::Kernel::Neon
    } else {
        leaf::Kernel::Avx2
    };
    if !kernel.compiled() {
        assert!(std::env::var_os("BRYNJA_REQUIRE_SCOPED_MULTIBUFFER").is_none());
        return Ok(());
    }
    // NEON leaves need no SHA3 extension; the single-state static root does.
    // Validate the two capabilities independently, including root rejection.
    let root_kernel = if cfg!(target_arch = "aarch64") {
        RootKernel::ArmKeccak
    } else {
        RootKernel::X86Keccak
    };
    let root_available = root_kernel.check_compiled_target().is_ok();
    if !root_available {
        assert!(std::env::var_os("BRYNJA_REQUIRE_SCOPED_MULTIBUFFER").is_none());
    }
    for identity in [
        Identity::ParallelHash128,
        Identity::ParallelHash256,
        Identity::ParallelHashXof128,
        Identity::ParallelHashXof256,
    ] {
        let input = [0x15; 32];
        let request = request(identity, &input, 5, 4)?;
        let mut expected = [0; 173];
        reference(&request, &mut expected)?;
        for root in [Preference::Portable, Preference::RequireStatic] {
            for leaves in [Preference::Portable, Preference::RequireStatic] {
                let mut cfg = config(3, leaves);
                cfg.root = root;
                let executor = Executor::new(cfg)?;
                let token = CancellationToken::new();
                let mut output = [0xa5; 173];
                let mut scratch = [0xa5; 180];
                if root == Preference::RequireStatic && !root_available {
                    assert!(matches!(
                        executor.hash_public_bits(&request, &mut output, 5, &mut scratch, &token),
                        Err(Error::Scheduling(crate::execution::Error::Static(
                            StaticError::MissingTargetFeatures
                        )))
                    ));
                    assert_eq!(output, [0xa5; 173]);
                    assert_eq!(scratch, [0; 180]);
                    assert!(matches!(
                        executor.hash_secret_bits(&request, &mut output, 5, &token),
                        Err(Error::Scheduling(crate::execution::Error::Static(
                            StaticError::MissingTargetFeatures
                        )))
                    ));
                    assert_eq!(output, [0; 173]);
                    continue;
                }
                let report =
                    executor.hash_public_bits(&request, &mut output, 5, &mut scratch, &token)?;
                assert_eq!(output, expected);
                assert_eq!(scratch, [0; 180]);
                assert_eq!(
                    report.execution.root.is_some(),
                    root == Preference::RequireStatic
                );
                assert_eq!(
                    report.execution.accelerated_leaves,
                    if leaves == Preference::RequireStatic {
                        8
                    } else {
                        0
                    }
                );
                assert_eq!(report.vector_calls > 0, leaves == Preference::RequireStatic);
                assert_eq!(report.execution.thread_width, 2);
                assert_eq!(report.groups, 2);
                let (secret, second) =
                    executor.hash_secret_bits(&request, &mut output, 5, &token)?;
                assert_eq!(secret.expose(), expected);
                assert_eq!(second, report);
                drop(secret);
                assert_eq!(output, [0; 173]);
            }
        }
    }
    Ok(())
}

#[test]
fn scoped_multibuffer_invalid_config_short_stage_and_poison() -> Result<(), Error> {
    for workers in [0, 65] {
        assert!(Executor::new(config(workers, Preference::Portable)).is_err());
    }
    let mut cfg = config(2, Preference::Portable);
    cfg.minimum_permutations = 0;
    assert!(Executor::new(cfg).is_err());
    let mut cfg = config(2, Preference::Portable);
    cfg.max_leaves = 0;
    assert!(Executor::new(cfg).is_err());
    let executor = Executor::new(config(2, Preference::Portable))?;
    let request = request(Identity::ParallelHashXof256, b"AB", 8, 1)?;
    let mut output = [0xa5; 9];
    let mut scratch = [0xa5; 8];
    let token = CancellationToken::new();
    assert!(
        executor
            .hash_public(&request, &mut output, &mut scratch, &token)
            .is_err()
    );
    assert_eq!(output, [0xa5; 9]);
    assert_eq!(scratch, [0; 8]);
    let (value, _) = executor.hash_secret_bits(&request, &mut [], 0, &token)?;
    drop(value);
    assert!(
        executor
            .hash_secret_bits(&request, &mut [], 8, &token)
            .is_err()
    );
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<(), Error> {
        let _gate = executor.inner.base.gate()?;
        std::panic::resume_unwind(Box::new(()));
    }));
    assert!(caught.is_err());
    assert!(executor.hash_secret(&request, &mut output, &token).is_err());
    assert_eq!(output, [0; 9]);
    output.fill(0xa5);
    scratch.fill(0xa5);
    assert!(
        executor
            .hash_public(&request, &mut output, &mut scratch, &token)
            .is_err()
    );
    assert_eq!(output, [0xa5; 9]);
    assert_eq!(scratch, [0; 8]);
    Ok(())
}
