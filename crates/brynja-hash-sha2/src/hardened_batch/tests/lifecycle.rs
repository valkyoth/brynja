use super::*;
use std::{
    boxed::Box,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
};

#[test]
fn focused_unwind_after_secret_processing_clears_and_revokes() -> Result<(), Error> {
    let b = bits(&[0x63; 128], 8)?;
    let inputs = [
        Some(Input::new(Algorithm::Sha256, b)),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    ];
    for secret in [false, true] {
        let executor = Executor::portable();
        let mut storage = [[0xa5; 32]; CAPACITY];
        let mut workspace = Workspace::new();
        poison(&mut workspace);
        let mut polls = 0_usize;
        let mut cancel = || {
            polls = polls.saturating_add(1);
            if polls == 3 {
                resume_unwind(Box::new("after first scalar compression"));
            }
            false
        };
        let mut control = Control::new(3, &mut cancel);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                if secret {
                    executor
                        .digest_secret(
                            &inputs,
                            destinations(&mut storage, &inputs),
                            &mut workspace,
                            &mut control,
                        )
                        .map(|(owner, report)| {
                            drop(owner);
                            report
                        })
                } else {
                    executor.digest_public(
                        &inputs,
                        destinations(&mut storage, &inputs),
                        &mut workspace,
                        &mut control,
                        PublicDeclassification::acknowledge(),
                    )
                }
            }))
            .is_err()
        );
        assert_eq!(control.used(), 1);
        assert_eq!(storage.first(), Some(&[if secret { 0 } else { 0xa5 }; 32]));
        assert!(storage.iter().skip(1).all(|slot| *slot == [0xa5; 32]));
        assert_eq!(executor.check(), Err(Error::Quarantined));
        cleared(&workspace);
    }
    Ok(())
}

#[test]
fn every_wrong_slot_width_clears_secret_and_preserves_public() -> Result<(), Error> {
    for active in [false, true] {
        for bad_slot in 0..CAPACITY {
            for width in 0..=33 {
                if active && width == 32 {
                    continue;
                }
                let b = bits(b"abc", 8)?;
                let inputs = core::array::from_fn(|index| {
                    (active || index != bad_slot).then(|| Input::new(Algorithm::Sha256, b))
                });
                for secret in [false, true] {
                    let executor = Executor::portable();
                    let mut storage = [[0xa5; 33]; CAPACITY];
                    let mut index = 0_usize;
                    let dest = storage.each_mut().map(|out| {
                        let size = if index == bad_slot { width } else { 32 };
                        index = index.saturating_add(1);
                        out.get_mut(..size)
                    });
                    let mut workspace = Workspace::new();
                    poison(&mut workspace);
                    let mut cancel = || false;
                    let mut control = Control::new(8, &mut cancel);
                    if secret {
                        assert!(matches!(
                            executor.digest_secret(&inputs, dest, &mut workspace, &mut control),
                            Err(Error::OutputShape)
                        ));
                    } else {
                        assert_eq!(
                            executor.digest_public(
                                &inputs,
                                dest,
                                &mut workspace,
                                &mut control,
                                PublicDeclassification::acknowledge()
                            ),
                            Err(Error::OutputShape)
                        );
                    }
                    for (index, out) in storage.iter().enumerate() {
                        let size = if index == bad_slot { width } else { 32 };
                        assert!(
                            out.get(..size)
                                .ok_or(Error::Invariant)?
                                .iter()
                                .all(|byte| *byte == if secret { 0 } else { 0xa5 })
                        );
                        assert!(
                            out.get(size..)
                                .ok_or(Error::Invariant)?
                                .iter()
                                .all(|byte| *byte == 0xa5)
                        );
                    }
                    assert_eq!(control.used(), 0);
                    cleared(&workspace);
                    executor.check()?;
                }
            }
        }
    }
    Ok(())
}
fn work_failures(executor: &Executor<'_>) -> Result<(), Error> {
    let data = [0x63; 128];
    let b = bits(&data, 8)?;
    let inputs = core::array::from_fn(|_| Some(Input::new(Algorithm::Sha256, b)));
    for budget in 0..24 {
        for secret in [false, true] {
            let mut storage = [[0xa5; 32]; CAPACITY];
            let mut workspace = Workspace::new();
            let mut cancel = || false;
            let mut control = Control::new(budget, &mut cancel);
            if secret {
                assert!(matches!(
                    executor.digest_secret(
                        &inputs,
                        destinations(&mut storage, &inputs),
                        &mut workspace,
                        &mut control
                    ),
                    Err(Error::WorkLimit)
                ));
            } else {
                assert_eq!(
                    executor.digest_public(
                        &inputs,
                        destinations(&mut storage, &inputs),
                        &mut workspace,
                        &mut control,
                        PublicDeclassification::acknowledge()
                    ),
                    Err(Error::WorkLimit)
                );
            }
            assert_eq!(storage, [[if secret { 0 } else { 0xa5 }; 32]; CAPACITY]);
            assert!(control.used() <= budget);
            cleared(&workspace);
            reusable(executor)?;
        }
    }
    Ok(())
}
#[test]
fn work_limit_is_not_persistent_quarantine() -> Result<(), Error> {
    work_failures(&Executor::portable())?;
    for kernel in [Kernel::Avx2, Kernel::Neon] {
        if !kernel.compiled() {
            continue;
        }
        let authority = Authority::for_compiled_target(kernel).map_err(Error::Backend)?;
        let executor = Executor::with_session(
            authority.session().map_err(Error::Backend)?,
            Mode::Require,
            1,
        )?;
        work_failures(&executor)?;
    }
    Ok(())
}
fn cancellation_boundaries(kernel: Option<Kernel>) -> Result<(), Error> {
    let b = bits(&[0x63; 128], 8)?;
    let inputs = core::array::from_fn(|_| Some(Input::new(Algorithm::Sha256, b)));
    let mut reached_success = false;
    for boundary in 0..=26 {
        for action in 0..3 {
            for secret in [false, true] {
                let authority = kernel
                    .map(Authority::for_compiled_target)
                    .transpose()
                    .map_err(Error::Backend)?;
                let executor = match &authority {
                    Some(owner) => Executor::with_session(
                        owner.session().map_err(Error::Backend)?,
                        Mode::Require,
                        1,
                    )?,
                    None => Executor::portable(),
                };
                let mut storage = [[0xa5; 32]; CAPACITY];
                let mut workspace = Workspace::new();
                let mut polls = 0_usize;
                let mut cancel = || {
                    let trigger = polls == boundary;
                    polls = polls.saturating_add(1);
                    if trigger && action == 1 {
                        executor.quarantine();
                    }
                    if trigger && action == 2 {
                        resume_unwind(Box::new("cancellation unwind probe"));
                    }
                    trigger && action == 0
                };
                let mut control = Control::new(24, &mut cancel);
                let outcome = catch_unwind(AssertUnwindSafe(|| {
                    if secret {
                        executor
                            .digest_secret(
                                &inputs,
                                destinations(&mut storage, &inputs),
                                &mut workspace,
                                &mut control,
                            )
                            .map(|(output, report)| {
                                drop(output);
                                report
                            })
                    } else {
                        executor.digest_public(
                            &inputs,
                            destinations(&mut storage, &inputs),
                            &mut workspace,
                            &mut control,
                            PublicDeclassification::acknowledge(),
                        )
                    }
                }));
                cleared(&workspace);
                let success = matches!(outcome, Ok(Ok(_)));
                if success {
                    reached_success = true;
                }
                if secret || !success {
                    assert_eq!(storage, [[if secret { 0 } else { 0xa5 }; 32]; CAPACITY]);
                }
                if polls > boundary {
                    match action {
                        0 => {
                            assert!(matches!(outcome, Ok(Err(Error::Cancelled))));
                            reusable(&executor)?;
                        }
                        1 => {
                            assert!(matches!(
                                outcome,
                                Ok(Err(Error::Quarantined | Error::Backend(_)))
                            ));
                            assert!(executor.check().is_err());
                        }
                        _ => {
                            assert!(outcome.is_err());
                            assert!(executor.check().is_err());
                        }
                    }
                } else {
                    assert!(success);
                    reusable(&executor)?;
                }
            }
        }
    }
    assert!(reached_success);
    Ok(())
}
#[test]
fn cancellation_revocation_and_unwind_at_every_boundary() -> Result<(), Error> {
    cancellation_boundaries(None)?;
    for kernel in [Kernel::Avx2, Kernel::Neon] {
        if kernel.compiled() {
            cancellation_boundaries(Some(kernel))?;
        }
    }
    Ok(())
}
#[test]
fn declassification_is_consuming_atomic_and_clears_originals() -> Result<(), Error> {
    let b = bits(b"abc", 8)?;
    let inputs = core::array::from_fn(|_| Some(Input::new(Algorithm::Sha256, b)));
    for bad in [false, true] {
        let mut secret = [[0xa5; 32]; CAPACITY];
        let mut public = [[0x69; 32]; CAPACITY];
        let mut workspace = Workspace::new();
        let mut cancel = || false;
        let mut control = Control::new(8, &mut cancel);
        let (owner, _) = Executor::portable().digest_secret(
            &inputs,
            destinations(&mut secret, &inputs),
            &mut workspace,
            &mut control,
        )?;
        let mut dest = destinations(&mut public, &inputs);
        if bad {
            dest[7] = None;
        }
        let result = owner.declassify(dest, PublicDeclassification::acknowledge());
        assert_eq!(secret, [[0; 32]; CAPACITY]);
        if bad {
            assert_eq!(result, Err(Error::OutputShape));
            assert_eq!(public, [[0x69; 32]; CAPACITY]);
        } else {
            result?;
            for (out, input) in public.iter().zip(inputs.iter().flatten()) {
                assert_eq!(*out, oracle(input)?);
            }
        }
        cleared(&workspace);
    }
    Ok(())
}
