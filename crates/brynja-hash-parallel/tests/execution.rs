//! Differential and fail-closed lifecycle tests for opt-in ParallelHash execution.
#![cfg(feature = "hardened-execution")]

use brynja_hash_parallel::{
    Fips202BitString, Fips202Output, ParallelHashPublicDeclassification as Public,
    execution::{Collector, Error, Identity, Mode, Plan, WorkerPolicy},
};

const IDENTITIES: [Identity; 4] = [
    Identity::ParallelHash128,
    Identity::ParallelHash256,
    Identity::ParallelHashXof128,
    Identity::ParallelHashXof256,
];
fn bits(bytes: &[u8], valid: u8) -> Result<Fips202BitString<'_>, Error> {
    Fips202BitString::new(bytes, valid).map_err(|_| Error::State)
}
fn xof(identity: Identity) -> bool {
    matches!(
        identity,
        Identity::ParallelHashXof128 | Identity::ParallelHashXof256
    )
}
fn reference(
    identity: Identity,
    input: Fips202BitString<'_>,
    block: usize,
    custom: Fips202BitString<'_>,
    output: &mut [u8],
    valid: u8,
) -> Result<(), Error> {
    macro_rules! run {
        ($plan:ident, $collector:ident, $size:literal) => {{
            let plan = brynja_hash_parallel::$plan::new_bits(input, block)?;
            let mut collector = brynja_hash_parallel::$collector::new_bits(&plan, custom)?;
            for index in 0..plan.leaf_count() {
                let mut storage = [0; $size];
                let result = plan.job(index)?.execute(&mut storage)?;
                collector.merge(&result)?;
            }
            let target = Fips202Output::new(output, valid).map_err(|_| Error::OutputLength)?;
            if xof(identity) {
                collector
                    .finalize_xof()?
                    .squeeze_final_bits_public(target, Public::acknowledge())?;
            } else {
                collector.finalize_bits(target)?;
            }
        }};
    }
    if identity.leaf_bytes() == 32 {
        run!(ParallelHash128Plan, ParallelHash128Collector, 32);
    } else {
        run!(ParallelHash256Plan, ParallelHash256Collector, 64);
    }
    Ok(())
}

#[test]
fn all_identities_bits_blocks_and_outputs_match_portable() -> Result<(), Error> {
    for identity in IDENTITIES {
        for block in [1, 8, 31, 64] {
            for length in [0, 1, 7, 8, 31, 64, 169] {
                let mut input = [0x31; 169];
                for valid in if length == 0 {
                    &[0][..]
                } else {
                    &[1, 7, 8][..]
                } {
                    if length != 0 {
                        *input.get_mut(length - 1).ok_or(Error::State)? =
                            0x31 & (u8::MAX >> (8 - valid));
                    }
                    let message = bits(input.get(..length).ok_or(Error::State)?, *valid)?;
                    let custom = bits(&[5], 3)?;
                    for (out_len, out_valid) in [(0, 0), (1, 3), (32, 8), (169, 7)] {
                        let mut expected = vec![0; out_len];
                        reference(identity, message, block, custom, &mut expected, out_valid)?;
                        let plan = Plan::new_bits(identity, message, block, 256)?;
                        let mut root = Collector::new_bits(&plan, Mode::Prefer(None), custom)?;
                        root.execute_serial(|_| Ok(Mode::Portable))?;
                        assert_eq!(root.merged_leaves(), plan.leaf_count());
                        assert_eq!(root.accelerated_leaves(), 0);
                        let mut output = vec![0xa5; out_len];
                        let mut scratch = vec![0xa5; out_len + 11];
                        if xof(identity) {
                            root.finalize_xof()?.squeeze_final_public(
                                &mut output,
                                out_valid,
                                &mut scratch,
                                Public::acknowledge(),
                            )?;
                        } else {
                            root.finalize_public_bits(
                                &mut output,
                                out_valid,
                                &mut scratch,
                                Public::acknowledge(),
                            )?;
                        }
                        assert_eq!(output, expected);
                        assert!(scratch.iter().all(|b| *b == 0));
                    }
                }
            }
        }
    }
    Ok(())
}

#[test]
fn wrong_duplicate_missing_and_reordered_leaves_close_root() -> Result<(), Error> {
    let plan = Plan::new(Identity::ParallelHash128, b"two leaf", 4, 2)?;
    let other = Plan::new(Identity::ParallelHash128, b"two leaf", 4, 2)?;
    for scenario in 0..4 {
        let mut root = Collector::new(&plan, Mode::Portable, b"")?;
        let mut storage = [0xa5; 32];
        let source = if scenario == 0 { &other } else { &plan };
        let index = u128::from(scenario == 1);
        let leaf = source.job(index)?.execute(Mode::Portable, &mut storage)?;
        if scenario == 2 {
            root.merge(&leaf)?;
        }
        if scenario != 3 {
            assert!(root.merge(&leaf).is_err());
        }
        let mut output = [0xa5; 32];
        assert!(root.finalize_secret(&mut output).is_err());
        assert_eq!(output, [0; 32]);
        drop(leaf);
        assert_eq!(storage, [0; 32]);
    }
    Ok(())
}

#[test]
fn selection_and_work_limits_never_authorize_fallback() -> Result<(), Error> {
    assert!(Plan::new(Identity::ParallelHash128, b"x", 1, 0).is_err());
    assert!(Plan::new(Identity::ParallelHash128, b"xx", 1, 1).is_err());
    let plan = Plan::new(Identity::ParallelHash128, b"x", 1, 1)?
        .with_worker_policy(WorkerPolicy::RequireAcceleration);
    let mut output = [0xa5; 32];
    assert!(matches!(
        plan.job(0)?.execute(Mode::Portable, &mut output),
        Err(Error::AccelerationUnavailable)
    ));
    assert_eq!(output, [0; 32]);
    assert!(matches!(
        Collector::new(&plan, Mode::Require(None), b""),
        Err(Error::AccelerationUnavailable)
    ));
    let mut root = Collector::new(&plan, Mode::Portable, b"")?;
    assert!(
        root.execute_serial(|_| Err(Error::AccelerationUnavailable))
            .is_err()
    );
    assert!(root.execute_serial(|_| Ok(Mode::Portable)).is_err());
    Ok(())
}

#[test]
fn secret_reader_and_public_failure_cleanup() -> Result<(), Error> {
    let plan = Plan::new(Identity::ParallelHashXof256, b"message", 4, 2)?;
    let mut root = Collector::new(&plan, Mode::Portable, b"scope")?;
    root.execute_serial(|_| Ok(Mode::Portable))?;
    let mut reader = root.finalize_xof()?;
    let mut output = [0xa5; 200];
    {
        let owned = reader.squeeze_secret(&mut output)?;
        assert_eq!(owned.expose().len(), 200);
    }
    assert_eq!(output, [0; 200]);
    output.fill(0xa5);
    let mut short = [0xa5; 3];
    assert!(
        reader
            .squeeze_public(&mut output, &mut short, Public::acknowledge())
            .is_err()
    );
    assert_eq!(output, [0xa5; 200]);
    assert_eq!(short, [0; 3]);
    assert!(reader.squeeze_secret(&mut output).is_err());
    assert_eq!(output, [0; 200]);
    drop(reader);
    assert!(root.finalize_xof().is_err());
    Ok(())
}

#[test]
fn serial_callback_unwind_cancels_root() -> Result<(), Error> {
    let plan = Plan::new(Identity::ParallelHash128, b"message", 4, 2)?;
    let mut root = Collector::new(&plan, Mode::Portable, b"")?;
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = root.execute_serial(|_| {
            assert_eq!(1, 2, "synthetic unwind");
            Ok(Mode::Portable)
        });
    }));
    assert!(caught.is_err());
    let mut output = [0xa5; 32];
    assert!(root.finalize_secret(&mut output).is_err());
    assert_eq!(output, [0; 32]);
    Ok(())
}

#[cfg(feature = "runtime-execution")]
#[test]
fn hosted_workers_and_root_match_reference_and_reject_quarantine() -> Result<(), Error> {
    use brynja_crypto_cpu::{hardened_execution::KeccakSession, static_execution::Kernel};
    use brynja_crypto_cpu_std::execution::{Authority, Mode as Hosted};
    let kernel = if cfg!(target_arch = "x86_64") {
        Kernel::X86Keccak
    } else {
        Kernel::ArmKeccak
    };
    let cpu_error = |e| Error::Execution(brynja_hash_sha3::hardened_execution::Error::Backend(e));
    let owner = Authority::new(kernel, Hosted::Prefer).map_err(|_| Error::State)?;
    if owner.session().map_err(|_| Error::State)?.is_none() {
        return Ok(());
    }
    let select = || {
        let raw = owner
            .session()
            .map_err(|_| Error::State)?
            .ok_or(Error::AccelerationUnavailable)?;
        Ok(Mode::Require(Some(
            KeccakSession::from_runtime(raw).map_err(cpu_error)?,
        )))
    };
    for identity in IDENTITIES {
        let plan = Plan::new(identity, b"accelerated leaves and root", 3, 32)?
            .with_worker_policy(WorkerPolicy::RequireAcceleration);
        let mut root = Collector::new(&plan, select()?, b"test")?;
        root.execute_serial(|_| select())?;
        assert_eq!(root.accelerated_leaves(), plan.leaf_count());
        assert_eq!(root.report().map(|r| r.kernel), Some(kernel));
        let mut expected = [0; 200];
        reference(
            identity,
            bits(b"accelerated leaves and root", 8)?,
            3,
            bits(b"test", 8)?,
            &mut expected,
            8,
        )?;
        let mut output = [0xa5; 200];
        let mut scratch = [0xa5; 200];
        if xof(identity) {
            root.finalize_xof()?.squeeze_public(
                &mut output,
                &mut scratch,
                Public::acknowledge(),
            )?;
        } else {
            root.finalize_public(&mut output, &mut scratch, Public::acknowledge())?;
        }
        assert_eq!(output, expected);
        assert_eq!(scratch, [0; 200]);
    }
    let plan = Plan::new(Identity::ParallelHash128, b"data", 8, 1)?;
    let mut root = Collector::new(&plan, select()?, b"")?;
    let stale = select()?;
    owner.quarantine();
    let mut output = [0xa5; 32];
    assert!(plan.job(0)?.execute(stale, &mut output).is_err());
    assert_eq!(output, [0; 32]);
    assert!(root.execute_serial(|_| Ok(Mode::Portable)).is_err());
    Ok(())
}
