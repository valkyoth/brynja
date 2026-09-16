use super::*;
use crate::execution::{Collector, Identity, Mode as RootMode, WorkerPolicy};
use crate::{Fips202BitString, Fips202Output, ParallelHashPublicDeclassification as Public};
extern crate std;
use std::{vec, vec::Vec};
std::thread_local! { static DROPS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) }; }
pub(super) fn observe_drop(workspace: &Workspace) {
    if workspace.values.iter().flatten().all(|v| *v == 0)
        && workspace.staging.iter().all(|v| *v == 0)
    {
        DROPS.with(|n| n.set(n.get().saturating_add(1)));
    }
}

const IDENTITIES: [Identity; 4] = [
    Identity::ParallelHash128,
    Identity::ParallelHash256,
    Identity::ParallelHashXof128,
    Identity::ParallelHashXof256,
];
fn cleared(workspace: &Workspace) {
    assert_eq!(workspace.values, [[0; 64]; CAPACITY]);
    assert_eq!(workspace.staging, [0; 256]);
}
fn reference(
    identity: Identity,
    input: Fips202BitString<'_>,
    block: usize,
    custom: Fips202BitString<'_>,
    out: &mut [u8],
    valid: u8,
) -> Result<(), Error> {
    let mut workspace = vec![0; block];
    let output = Fips202Output::new(out, valid).map_err(|_| RootError::State)?;
    macro_rules! fixed {
        ($ty:ty) => {
            <$ty>::new_bits(&mut workspace, custom)
                .map_err(RootError::from)?
                .finalize_bits(input, output)
                .map_err(RootError::from)?
        };
    }
    macro_rules! xof {
        ($ty:ty) => {
            <$ty>::new_bits(&mut workspace, custom)
                .map_err(RootError::from)?
                .finalize_bits_xof(input)
                .map_err(RootError::from)?
                .squeeze_final_bits(output)
                .map_err(RootError::from)?
        };
    }
    match identity {
        Identity::ParallelHash128 => fixed!(crate::ParallelHash128<'_>),
        Identity::ParallelHash256 => fixed!(crate::ParallelHash256<'_>),
        Identity::ParallelHashXof128 => xof!(crate::ParallelHashXof128<'_>),
        Identity::ParallelHashXof256 => xof!(crate::ParallelHashXof256<'_>),
    }
    Ok(())
}
fn campaign(executor: &Executor<'_>) -> Result<(), Error> {
    let kernel = executor.kernel()?;
    let mut workspace = Workspace::new();
    for identity in IDENTITIES {
        for block in [1_usize, 7, 136, 168] {
            for length in [
                0,
                1,
                block,
                block.saturating_mul(3).saturating_add(1),
                block.saturating_mul(4),
                block.saturating_mul(5).saturating_add(1),
                block.saturating_mul(9),
            ] {
                for valid in [1_u8, 8] {
                    let mut bytes: Vec<_> = (0..length)
                        .map(|i| i.to_le_bytes()[0].wrapping_mul(29))
                        .collect();
                    if let Some(last) = bytes.last_mut() {
                        *last &= 0xff_u8 >> 8_u8.saturating_sub(valid);
                    }
                    let input = Fips202BitString::new(&bytes, if length == 0 { 0 } else { valid })
                        .map_err(|_| RootError::State)?;
                    let custom = Fips202BitString::new(&[19], 5).map_err(|_| RootError::State)?;
                    let plan = Plan::new_bits(identity, input, block, 32)?;
                    let mut root = Collector::new_bits(&plan, RootMode::Portable, custom)?;
                    let mut cancelled = || false;
                    let report = root.execute_batched(
                        executor,
                        &mut workspace,
                        &mut Control::new(256, &mut cancelled),
                    )?;
                    assert_eq!(report.leaves, plan.leaf_count());
                    assert_eq!(report.accelerated_leaves, root.accelerated_leaves());
                    assert_eq!(
                        report.leaves,
                        report
                            .accelerated_leaves
                            .checked_add(report.scalar_leaves)
                            .ok_or(RootError::State)?
                    );
                    let accelerated = if let Some(k) = kernel {
                        plan.leaf_count()
                            .checked_div(k.width() as u128)
                            .and_then(|n| n.checked_mul(k.width() as u128))
                            .ok_or(RootError::State)?
                    } else {
                        0
                    };
                    assert_eq!(report.accelerated_leaves, accelerated);
                    assert_eq!(report.vector_calls > 0, accelerated > 0);
                    cleared(&workspace);
                    let mut expected = [0; 39];
                    reference(identity, input, block, custom, &mut expected, 5)?;
                    let mut output = expected.map(|byte| !byte);
                    if identity.xof() {
                        let secret = root.finalize_xof()?.squeeze_final_secret(&mut output, 5)?;
                        assert_eq!(secret.expose(), expected);
                        drop(secret);
                    } else {
                        let secret = root.finalize_secret_bits(&mut output, 5)?;
                        assert_eq!(secret.expose(), expected);
                        drop(secret);
                    }
                    assert_eq!(output, [0; 39]);
                }
            }
        }
    }
    Ok(())
}
#[test]
fn portable_domains_bits_boundaries_and_order() -> Result<(), Error> {
    campaign(&Executor::portable())
}
#[test]
fn vector_domains_bits_boundaries_and_actual_leaf_counts() -> Result<(), Error> {
    let kernel = if cfg!(target_arch = "aarch64") {
        Kernel::Neon
    } else {
        Kernel::Avx2
    };
    if !kernel.compiled() {
        assert!(std::env::var_os("BRYNJA_REQUIRE_PARALLELHASH_BATCH").is_none());
        return Ok(());
    }
    let owner = Authority::for_compiled_target(kernel).map_err(hash::Error::Backend)?;
    campaign(&Executor::with_session(
        owner.session().map_err(hash::Error::Backend)?,
        Mode::Prefer,
        1,
    )?)
}
#[test]
fn provenance_order_missing_and_duplicate_groups_fail_closed() -> Result<(), Error> {
    let plan = Plan::new(Identity::ParallelHash128, b"abcdefgh", 1, 8)?;
    let foreign = Plan::new(Identity::ParallelHash128, b"abcdefgh", 1, 8)?;
    for (source, start, duplicate) in [(&foreign, 0, false), (&plan, 1, false), (&plan, 0, true)] {
        let mut root = Collector::new(&plan, RootMode::Portable, b"")?;
        let mut workspace = Workspace::new();
        let mut no = || false;
        let executor = Executor::portable();
        if duplicate {
            root.merge_batch(plan.batch(0, 4)?.execute(
                &executor,
                &mut workspace,
                &mut Control::new(32, &mut no),
            )?)?;
        }
        let leaves = source.batch(start, 4)?.execute(
            &executor,
            &mut workspace,
            &mut Control::new(32, &mut no),
        )?;
        assert!(root.merge_batch(leaves).is_err());
        cleared(&workspace);
        assert_eq!(root.merged_leaves(), 0);
        assert!(root.execute_serial(|_| Ok(RootMode::Portable)).is_err());
        let mut output = [0xa5; 32];
        assert!(root.finalize_secret(&mut output).is_err());
        assert_eq!(output, [0; 32]);
    }
    for count in [0, 5, usize::MAX] {
        assert!(plan.batch(0, count).is_err());
    }
    assert!(plan.batch(u128::MAX, 1).is_err());
    let root = Collector::new(&plan, RootMode::Portable, b"")?;
    let mut output = [0xa5; 32];
    let mut scratch = [0xff; 32];
    assert!(
        root.finalize_public(&mut output, &mut scratch, Public::acknowledge())
            .is_err()
    );
    assert_eq!(output, [0xa5; 32]);
    assert_eq!(scratch, [0; 32]);
    Ok(())
}

#[test]
fn cancellation_budget_and_unwind_close_root_and_clear_every_slot() -> Result<(), Error> {
    let plan = Plan::new(Identity::ParallelHash256, &[0xa5; 1024], 128, 8)?;
    for boundary in 0_u64..24 {
        for action in 0..3 {
            let mut root = Collector::new(&plan, RootMode::Portable, b"")?;
            let mut workspace = Workspace::new();
            workspace.values = [[0xa5; 64]; CAPACITY];
            workspace.staging = [0xff; 256];
            let executor = Executor::portable();
            let mut calls = 0_u64;
            let mut cancellation = || {
                calls = calls.saturating_add(1);
                if action == 2 && calls == boundary {
                    std::panic::resume_unwind(std::boxed::Box::new(()));
                }
                action == 1 && calls == boundary
            };
            let limit = if action == 0 { boundary } else { 1000 };
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                root.execute_batched(
                    &executor,
                    &mut workspace,
                    &mut Control::new(limit, &mut cancellation),
                )
            }));
            cleared(&workspace);
            if !matches!(result, Ok(Ok(_))) {
                assert_eq!(root.merged_leaves(), 0);
                assert!(root.execute_serial(|_| Ok(RootMode::Portable)).is_err());
            }
        }
    }
    Ok(())
}

#[test]
fn worker_policy_is_not_a_forged_vector_report() -> Result<(), Error> {
    let plan = Plan::new(Identity::ParallelHash128, b"abcdefgh", 1, 8)?
        .with_worker_policy(WorkerPolicy::RequireAcceleration);
    let mut workspace = Workspace::new();
    let mut no = || false;
    let mut control = Control::new(32, &mut no);
    assert!(
        plan.batch(0, 4)?
            .execute(&Executor::portable(), &mut workspace, &mut control)
            .is_err()
    );
    assert_eq!(control.used(), 0);
    cleared(&workspace);
    Ok(())
}

#[test]
fn completed_owner_and_workspace_drop_clear_storage() -> Result<(), Error> {
    let plan = Plan::new(Identity::ParallelHash128, b"abcdefgh", 1, 8)?;
    let mut workspace = Workspace::new();
    let mut no = || false;
    let leaves = plan.batch(0, 3)?.execute(
        &Executor::portable(),
        &mut workspace,
        &mut Control::new(16, &mut no),
    )?;
    assert_eq!(leaves.len(), 3);
    assert!(!leaves.is_empty());
    drop(leaves);
    cleared(&workspace);
    workspace.values = [[0xa5; 64]; CAPACITY];
    workspace.staging = [0x5a; 256];
    let before = DROPS.with(core::cell::Cell::get);
    drop(workspace);
    assert_eq!(DROPS.with(core::cell::Cell::get), before.saturating_add(1));
    Ok(())
}

#[test]
fn scheduled_tokens_cannot_complete_streaming_roots() -> Result<(), Error> {
    let plan = Plan::new(Identity::ParallelHash128, b"abcd", 1, 4)?;
    let binding = crate::execution::binding::Binding::Streaming {
        identity: plan.identity(),
        block: 1,
        limit: 4,
        workers: WorkerPolicy::Mixed,
    };
    let mut root =
        Collector::from_binding(binding, RootMode::Portable, crate::execution::bits(&[])?)?;
    let mut workspace = Workspace::new();
    let mut no = || false;
    let leaves = plan.batch(0, 4)?.execute(
        &Executor::portable(),
        &mut workspace,
        &mut Control::new(16, &mut no),
    )?;
    assert!(root.merge_batch(leaves).is_err());
    cleared(&workspace);
    assert!(root.finalize_xof().is_err());
    assert!(root.execute_serial(|_| Ok(RootMode::Portable)).is_err());
    Ok(())
}

#[test]
fn required_tail_and_revoked_backend_never_silently_fall_back() -> Result<(), Error> {
    let kernel = if cfg!(target_arch = "aarch64") {
        Kernel::Neon
    } else {
        Kernel::Avx2
    };
    if !kernel.compiled() {
        return Ok(());
    }
    for action in 0..3 {
        let owner = Authority::for_compiled_target(kernel).map_err(hash::Error::Backend)?;
        let executor = Executor::with_session(
            owner.session().map_err(hash::Error::Backend)?,
            Mode::Require,
            1,
        )?;
        let plan = Plan::new(Identity::ParallelHash128, b"abcde", 1, 5)?;
        let mut root = Collector::new(&plan, RootMode::Portable, b"")?;
        let mut workspace = Workspace::new();
        let mut calls = 0_u64;
        let mut cancel = || {
            calls = calls.saturating_add(1);
            if action == 1 && calls == 2 {
                owner.quarantine();
            }
            false
        };
        if action == 2 {
            owner.quarantine();
        }
        assert!(
            root.execute_batched(
                &executor,
                &mut workspace,
                &mut Control::new(64, &mut cancel)
            )
            .is_err()
        );
        cleared(&workspace);
        assert_eq!(root.merged_leaves(), 0);
        let mut out = [0xa5; 32];
        let mut scratch = [0xff; 32];
        assert!(
            root.finalize_public(&mut out, &mut scratch, Public::acknowledge())
                .is_err()
        );
        assert_eq!(out, [0xa5; 32]);
        assert_eq!(scratch, [0; 32]);
    }
    let owner = Authority::for_compiled_target(kernel).map_err(hash::Error::Backend)?;
    let executor = Executor::with_session(
        owner.session().map_err(hash::Error::Backend)?,
        Mode::Prefer,
        1,
    )?;
    for workers in [WorkerPolicy::Portable, WorkerPolicy::RequireAcceleration] {
        let plan =
            Plan::new(Identity::ParallelHash128, b"abcde", 1, 5)?.with_worker_policy(workers);
        let mut root = Collector::new(&plan, RootMode::Portable, b"")?;
        let mut workspace = Workspace::new();
        let mut no = || false;
        assert!(
            root.execute_batched(&executor, &mut workspace, &mut Control::new(64, &mut no))
                .is_err()
        );
        cleared(&workspace);
    }
    Ok(())
}
