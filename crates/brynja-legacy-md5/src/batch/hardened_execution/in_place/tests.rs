use super::*;
use crate::{Md5BackendHealth, owner::Md5Owner};
extern crate std;
use std::panic::{AssertUnwindSafe, catch_unwind};
type TestResult = Result<(), std::boxed::Box<dyn std::error::Error>>;

fn cleared(workspace: &Workspace<'_>) {
    for owner in &workspace.batch.owner.lanes {
        assert_eq!(owner.chaining_state, [0; 16]);
        assert_eq!(owner.block, [0; 64]);
        assert_eq!(owner.message_length, [0; 16]);
        assert_eq!(owner.buffered, [0; 1]);
        assert_eq!(owner.output_staging, [0; 16]);
    }
}
fn poison(batch: &mut super::super::Batch<'_>) {
    for owner in &mut batch.owner.lanes {
        owner.chaining_state.fill(0xa5);
        owner.block.fill(0xa5);
        owner.message_length.fill(0xa5);
        owner.buffered.fill(0xa5);
        owner.output_staging.fill(0xa5);
    }
}
fn reusable(workspace: &mut Workspace<'_>) -> TestResult {
    let inputs = [Some(BitString::new(b"abc", 8).map_err(|_| "bits")?); 8];
    let mut output = [[0xa5; 16]; 8];
    let (secret, report) = workspace
        .with(|batch| batch.digest_secret(&inputs, &mut output, &mut Md5BatchControl::new(8)))??;
    assert_eq!(secret.expose(), [crate::md5(b"abc")?; 8].as_flattened());
    assert_eq!(report.work.active_lanes, 8);
    cleared(workspace);
    drop(secret);
    assert_eq!(output, [[0; 16]; 8]);
    assert_eq!(workspace.batch.executor.health(), Md5BackendHealth::Healthy);
    Ok(())
}

#[test]
fn scoped_batch_reset_forget_cancel_and_reuse() -> TestResult {
    let executor = Executor::portable();
    let mut workspace = Workspace::new(&executor);
    poison(&mut workspace.batch);
    workspace.with(|batch| {
        for lane in &batch.batch.owner.lanes {
            assert_eq!(lane.chaining_state, Md5Owner::new().chaining_state);
            assert_eq!(lane.block, [0; 64]);
            assert_eq!(lane.message_length, [0; 16]);
            assert_eq!(lane.buffered, [0; 1]);
            assert_eq!(lane.output_staging, [0; 16]);
        }
        poison(batch.batch);
        core::mem::forget(batch);
    })?;
    cleared(&workspace);
    reusable(&mut workspace)?;
    // The handle's own destructor must clear before the parent scope exits.
    poison(&mut workspace.batch);
    Batch {
        batch: &mut workspace.batch,
    }
    .cancel();
    cleared(&workspace);
    reusable(&mut workspace)
}

#[test]
fn scoped_batch_empty_and_inactive_output_is_not_stale() -> TestResult {
    let executor = Executor::portable();
    let mut workspace = Workspace::new(&executor);
    for active in [false, true] {
        let mut inputs = [None; 8];
        if active {
            inputs[3] = Some(BitString::new(&[], 0).map_err(|_| "bits")?);
        }
        let mut expected = [[0; 16]; 8];
        if active {
            expected[3] = crate::md5(b"")?;
        }
        let mut output = [[0xa5; 16]; 8];
        let report = workspace.with(|batch| {
            batch.digest_public(
                &inputs,
                &mut output,
                &mut Md5BatchControl::new(8),
                PublicDeclassification::acknowledge(),
            )
        })??;
        assert_eq!(output, expected);
        assert_eq!(report.work.active_lanes, usize::from(active));
        cleared(&workspace);
        let (secret, secret_report) = workspace.with(|batch| {
            batch.digest_secret(&inputs, &mut output, &mut Md5BatchControl::new(8))
        })??;
        assert_eq!(secret.expose(), expected.as_flattened());
        assert_eq!(secret_report, report);
        drop(secret);
        assert_eq!(output, [[0; 16]; 8]);
        cleared(&workspace);
    }
    Ok(())
}

#[test]
fn scoped_batch_budget_failures_preserve_executor_and_clear_all_lanes() -> TestResult {
    let executor = Executor::portable();
    let mut workspace = Workspace::new(&executor);
    let bytes = [0x36; 128];
    let inputs = [Some(BitString::new(&bytes, 8).map_err(|_| "bits")?); 8];
    for budget in 0..24 {
        let mut public = [[0xa5; 16]; 8];
        assert_eq!(
            workspace.with(|batch| batch.digest_public(
                &inputs,
                &mut public,
                &mut Md5BatchControl::new(budget),
                PublicDeclassification::acknowledge(),
            ))?,
            Err(Error::Batch(Md5BatchError::WorkLimit))
        );
        assert_eq!(public, [[0xa5; 16]; 8]);
        cleared(&workspace);
        let mut secret = [[0xa5; 16]; 8];
        assert!(matches!(
            workspace.with(|batch| batch.digest_secret(
                &inputs,
                &mut secret,
                &mut Md5BatchControl::new(budget),
            ))?,
            Err(Error::Batch(Md5BatchError::WorkLimit))
        ));
        assert_eq!(secret, [[0; 16]; 8]);
        cleared(&workspace);
        reusable(&mut workspace)?;
    }
    Ok(())
}

#[test]
fn scoped_batch_ineligible_and_length_rejection_preserve_health() -> TestResult {
    let mut executor = Executor::portable();
    executor.required = true;
    let mut workspace = Workspace::new(&executor);
    let mut output = [[0xa5; 16]; 8];
    assert!(matches!(
        workspace.with(|batch| batch.digest_secret(
            &[None; 8],
            &mut output,
            &mut Md5BatchControl::new(0),
        ))?,
        Err(Error::IneligibleWorkload)
    ));
    assert_eq!(output, [[0; 16]; 8]);
    cleared(&workspace);
    assert_eq!(executor.health(), Md5BackendHealth::Healthy);
    let executor = Executor::portable();
    let mut workspace = Workspace::new(&executor);
    let inputs = [Some(BitString::new(b"abc", 8).map_err(|_| "bits")?); 8];
    for secret in [false, true] {
        output.fill([0xa5; 16]);
        let result = workspace.with(|batch| {
            for lane in &mut batch.batch.owner.lanes {
                lane.message_length = (u128::MAX - 7).to_be_bytes();
            }
            if secret {
                batch
                    .digest_secret(&inputs, &mut output, &mut Md5BatchControl::new(8))
                    .map(|(owner, report)| {
                        drop(owner);
                        report
                    })
            } else {
                batch.digest_public(
                    &inputs,
                    &mut output,
                    &mut Md5BatchControl::new(8),
                    PublicDeclassification::acknowledge(),
                )
            }
        })?;
        assert_eq!(result, Err(Error::Batch(Md5BatchError::MessageTooLong)));
        assert_eq!(
            output,
            if secret {
                [[0; 16]; 8]
            } else {
                [[0xa5; 16]; 8]
            }
        );
        cleared(&workspace);
        reusable(&mut workspace)?;
    }
    Ok(())
}

#[test]
fn scoped_batch_callback_unwind_and_failed_admission_clear_storage() {
    for forget in [false, true] {
        let executor = Executor::portable();
        let mut workspace = Workspace::new(&executor);
        assert!(
            catch_unwind(AssertUnwindSafe(|| workspace.with(|batch| {
                poison(batch.batch);
                if forget {
                    core::mem::forget(batch);
                }
                std::panic::resume_unwind(std::boxed::Box::new(()));
            })))
            .is_err()
        );
        cleared(&workspace);
        assert_eq!(executor.health(), Md5BackendHealth::Quarantined);
        poison(&mut workspace.batch);
        let mut called = false;
        let mut captured = [0xa5; 16];
        assert_eq!(
            workspace.with(|_| {
                called = true;
                captured.fill(0);
            }),
            Err(Error::Quarantined)
        );
        assert!(!called);
        assert_eq!(captured, [0xa5; 16]);
        cleared(&workspace);
    }
}

#[test]
fn scoped_batch_cancel_revocation_and_operation_unwind() -> TestResult {
    let bytes = [0x36; 128];
    let inputs = [Some(BitString::new(&bytes, 8).map_err(|_| "bits")?); 8];
    for failure in 0..3 {
        for secret in [false, true] {
            let executor = Executor::portable();
            let mut workspace = Workspace::new(&executor);
            let mut output = [[0xa5; 16]; 8];
            let mut calls = 0;
            let mut callback = || {
                calls += 1;
                if calls != 3 {
                    return false;
                }
                match failure {
                    0 => true,
                    1 => {
                        executor.quarantine();
                        false
                    }
                    _ => std::panic::resume_unwind(std::boxed::Box::new(())),
                }
            };
            let result = catch_unwind(AssertUnwindSafe(|| {
                workspace.with(|batch| {
                    let mut control = Md5BatchControl::with_cancellation(24, &mut callback);
                    if secret {
                        batch.digest_secret(&inputs, &mut output, &mut control).map(
                            |(owner, report)| {
                                drop(owner);
                                report
                            },
                        )
                    } else {
                        batch.digest_public(
                            &inputs,
                            &mut output,
                            &mut control,
                            PublicDeclassification::acknowledge(),
                        )
                    }
                })
            }));
            if failure == 2 {
                assert!(result.is_err());
            } else {
                let result = result.map_err(|_| "unexpected unwind")??;
                assert_eq!(
                    result,
                    Err(if failure == 0 {
                        Error::Batch(Md5BatchError::Cancelled)
                    } else {
                        Error::Quarantined
                    })
                );
            }
            assert_eq!(
                output,
                if secret {
                    [[0; 16]; 8]
                } else {
                    [[0xa5; 16]; 8]
                }
            );
            cleared(&workspace);
            if failure == 0 {
                reusable(&mut workspace)?;
            } else {
                assert_eq!(executor.health(), Md5BackendHealth::Quarantined);
            }
        }
    }
    Ok(())
}
