use super::*;
extern crate std;
use crate::{Sha1BackendHealth, hardened_execution::Mode};
use std::panic::{AssertUnwindSafe, catch_unwind};

fn cleared(state: &Storage<'_>) {
    assert!(!state.active);
    assert_eq!(state.owner.chaining_state, [0; 20]);
    assert_eq!(state.owner.block, [0; 64]);
    assert_eq!(state.owner.schedule, [0; 320]);
    assert_eq!(state.owner.message_length, [0; 8]);
    assert_eq!(state.owner.buffered, [0]);
    assert_eq!(state.owner.output_staging, [0; 20]);
}
fn poison(owner: &mut Sha1Owner) {
    owner.chaining_state.fill(0xa5);
    owner.block.fill(0xa5);
    owner.schedule.fill(0xa5);
    owner.message_length.fill(0xa5);
    owner.buffered.fill(0xa5);
    owner.output_staging.fill(0xa5);
}

#[test]
fn scoped_execution_streams_bits_and_reuses_cleared_storage() -> Result<(), Error> {
    for executor in [
        Executor::portable(),
        Executor::for_compiled_target(Mode::Prefer)?,
    ] {
        let mut workspace = Sha1Workspace::new(&executor);
        let bytes = [0xab; 257];
        for count in [0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 257] {
            let input = bytes.get(..count).ok_or(Sha1Error::MessageTooLong)?;
            for tail_bits in 0..8 {
                let tail_byte = [0x80];
                let tail = if tail_bits == 0 {
                    empty()?
                } else {
                    BitString::new(&tail_byte, tail_bits).map_err(|_| Sha1Error::MessageTooLong)?
                };
                let mut reference = crate::hardened_in_place::Sha1Workspace::new();
                let mut expected = [0; 20];
                reference.with(|mut s| {
                    s.update(input)?;
                    s.finalize_bits_public(
                        tail,
                        &mut expected,
                        PublicDeclassification::acknowledge(),
                    )
                })?;
                poison(&mut workspace.state.owner);
                let mut public = [0xa5; 20];
                workspace.with(|mut s| {
                    assert_eq!(
                        s.state.owner.chaining_state,
                        Sha1Owner::new().chaining_state
                    );
                    assert_eq!(s.state.owner.block, [0; 64]);
                    assert_eq!(s.state.owner.schedule, [0; 320]);
                    assert_eq!(s.state.owner.message_length, [0; 8]);
                    assert_eq!(s.state.owner.buffered, [0]);
                    assert_eq!(s.state.owner.output_staging, [0; 20]);
                    for chunk in input.chunks(7) {
                        s.update(chunk)?;
                    }
                    s.update(&[])?;
                    s.finalize_bits_public(tail, &mut public, PublicDeclassification::acknowledge())
                })??;
                assert_eq!(public, expected);
                cleared(&workspace.state);
                let mut secret = [0xa5; 20];
                let output = workspace.with(|mut s| {
                    for chunk in input.chunks(63) {
                        s.update(chunk)?;
                    }
                    s.finalize_bits_secret(tail, &mut secret)
                })??;
                cleared(&workspace.state);
                assert_eq!(output.expose(), expected);
                drop(output);
                assert_eq!(secret, [0; 20]);
            }
        }
        assert_eq!(executor.report().health, Sha1BackendHealth::Healthy);
    }
    Ok(())
}

#[test]
fn scoped_execution_forget_cancel_and_scope_unwind() -> Result<(), Error> {
    for unwind in [false, true] {
        let executor = Executor::portable();
        let mut workspace = Sha1Workspace::new(&executor);
        let result = catch_unwind(AssertUnwindSafe(|| {
            workspace.with(|s| {
                poison(&mut s.state.owner);
                core::mem::forget(s);
                if unwind {
                    std::panic::resume_unwind(std::boxed::Box::new("scope"));
                }
            })
        }));
        assert_eq!(result.is_err(), unwind);
        cleared(&workspace.state);
        assert_eq!(
            executor.report().health,
            if unwind {
                Sha1BackendHealth::Quarantined
            } else {
                Sha1BackendHealth::Healthy
            }
        );
        if !unwind {
            // Isolate handle Drop from the enclosing scope guard.
            workspace.state.active = true;
            poison(&mut workspace.state.owner);
            Sha1 {
                state: &mut workspace.state,
            }
            .cancel();
            cleared(&workspace.state);
        }
    }
    Ok(())
}

#[test]
fn scoped_execution_length_failure_is_terminal_not_executor_failure() -> Result<(), Error> {
    let executor = Executor::portable();
    let mut workspace = Sha1Workspace::new(&executor);
    workspace.with(|mut s| {
        s.update(b"secret")?;
        s.state.owner.message_length = (u64::MAX - 7).to_be_bytes();
        assert_eq!(s.update(b"x"), Err(Sha1Error::MessageTooLong.into()));
        cleared(s.state);
        assert_eq!(s.update(b""), Err(Sha1Error::StateConsumed.into()));
        let mut destination = [0xa5; 20];
        assert!(s.finalize_secret(&mut destination).is_err());
        assert_eq!(destination, [0; 20]);
        Ok::<(), Error>(())
    })??;
    cleared(&workspace.state);
    assert_eq!(executor.report().health, Sha1BackendHealth::Healthy);
    workspace.with(|s| s.cancel())?;
    Ok(())
}

#[test]
fn scoped_execution_revocation_and_invariant_never_fall_back() -> Result<(), Error> {
    for corrupt in [false, true] {
        let executor = Executor::portable();
        let mut workspace = Sha1Workspace::new(&executor);
        workspace.with(|mut s| {
            s.update(b"secret")?;
            if corrupt {
                s.state.owner.buffered = [64];
            } else {
                executor.quarantine();
            }
            assert!(s.update(b"x").is_err());
            cleared(s.state);
            assert_eq!(s.update(b""), Err(Sha1Error::StateConsumed.into()));
            Ok::<(), Error>(())
        })??;
        cleared(&workspace.state);
        assert_eq!(executor.report().health, Sha1BackendHealth::Quarantined);
        let mut called = false;
        assert!(workspace.with(|_| called = true).is_err());
        assert!(!called);
        cleared(&workspace.state);
    }
    Ok(())
}

#[test]
fn scoped_execution_operation_unwind_clears_before_catch() -> Result<(), Error> {
    let executor = Executor::portable();
    let mut workspace = Sha1Workspace::new(&executor);
    workspace.with(|mut s| {
        s.update(b"secret")?;
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let _: Result<(), Error> = s.state.operate(|_, _| {
                    std::panic::resume_unwind(std::boxed::Box::new("operation"));
                });
            }))
            .is_err()
        );
        cleared(s.state);
        assert!(s.update(b"later").is_err());
        Ok::<(), Error>(())
    })??;
    assert_eq!(executor.report().health, Sha1BackendHealth::Quarantined);
    Ok(())
}

#[test]
fn scoped_execution_destinations_on_rejection() -> Result<(), Error> {
    for length in 0..=40 {
        if length == 20 {
            continue;
        }
        let executor = Executor::portable();
        let mut workspace = Sha1Workspace::new(&executor);
        let mut destination = [0xa5; 40];
        let (output, canary) = destination
            .split_at_mut_checked(length)
            .ok_or(Sha1Error::OutputLength)?;
        workspace.with(|s| assert!(s.finalize_secret(output).is_err()))?;
        assert!(output.iter().all(|b| *b == 0));
        assert!(canary.iter().all(|b| *b == 0xa5));
        destination.fill(0xa5);
        let output = destination
            .get_mut(..length)
            .ok_or(Sha1Error::OutputLength)?;
        workspace.with(|s| {
            assert!(
                s.finalize_public(output, PublicDeclassification::acknowledge())
                    .is_err()
            )
        })?;
        assert_eq!(destination, [0xa5; 40]);
        assert_eq!(executor.report().health, Sha1BackendHealth::Healthy);
        cleared(&workspace.state);
    }
    for secret in [false, true] {
        let executor = Executor::portable();
        let mut workspace = Sha1Workspace::new(&executor);
        let mut destination = [0xa5; 20];
        workspace.with(|mut s| {
            s.update(b"secret")?;
            executor.quarantine();
            if secret {
                assert!(s.finalize_secret(&mut destination).is_err());
            } else {
                assert!(
                    s.finalize_public(&mut destination, PublicDeclassification::acknowledge())
                        .is_err()
                );
            }
            Ok::<(), Error>(())
        })??;
        assert_eq!(destination, if secret { [0; 20] } else { [0xa5; 20] });
        cleared(&workspace.state);
    }
    Ok(())
}
