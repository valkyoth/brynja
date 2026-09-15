use super::*;
#[test]
fn focused_unwind_after_permutation_clears_every_owned_region() -> Result<(), Error> {
    let inputs = [
        Some(Input::new(Algorithm::Sha3_256, bits(b"secret", 48)?, 256)?),
        None,
        None,
        None,
    ];
    let mut out = [0xa5; 32];
    let mut stage = [0x72; 35];
    let mut workspace = Workspace::new();
    let executor = Executor::portable();
    let mut calls = 0;
    let mut cancel = || {
        calls += 1;
        if calls == 3 {
            std::panic::resume_unwind(std::boxed::Box::new("after permutation"));
        }
        false
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        executor
            .digest_secret(
                &inputs,
                [Some(&mut out), None, None, None],
                &mut workspace,
                &mut stage,
                &mut Control::new(1, &mut cancel),
            )
            .map(|_| ())
    }));
    assert!(result.is_err());
    assert_eq!(out, [0; 32]);
    assert_eq!(stage, [0; 35]);
    assert!(cleared(&workspace));
    assert!(executor.revoked.get());
    Ok(())
}
#[test]
fn inactive_destination_and_required_ineligibility_fail_before_work() -> Result<(), Error> {
    let mut out = [0xa5; 1];
    let mut stage = [0xa6; 5];
    let mut workspace = Workspace::new();
    let mut cancel = || false;
    assert!(matches!(
        Executor::portable().digest_secret(
            &[None, None, None, None],
            [None, Some(&mut out), None, None],
            &mut workspace,
            &mut stage,
            &mut Control::new(0, &mut cancel)
        ),
        Err(Error::InvalidDestination)
    ));
    assert_eq!(out, [0]);
    assert_eq!(stage, [0; 5]);
    for kernel in [Kernel::Avx2, Kernel::Neon] {
        if !kernel.compiled() {
            continue;
        }
        let authority = Authority::for_compiled_target(kernel).map_err(Error::Backend)?;
        let executor = Executor::with_session(
            authority.session().map_err(Error::Backend)?,
            Mode::Require,
            usize::MAX,
        )?;
        let inputs = inputs()?;
        let mut outputs = core::array::from_fn(|_| vec![0xa5; 338]);
        let mut staging = vec![0xa6; 1352];
        let mut control = Control::new(100, &mut cancel);
        assert!(matches!(
            executor.digest_secret(
                &inputs,
                destinations(&mut outputs),
                &mut workspace,
                &mut staging,
                &mut control
            ),
            Err(Error::IneligibleWorkload)
        ));
        assert_eq!(control.used(), 0);
        assert!(!executor.revoked.get());
        assert_eq!(
            authority
                .session()
                .map_err(Error::Backend)?
                .completed_vector_calls(),
            0
        );
        assert!(outputs.iter().flatten().all(|v| *v == 0));
        assert!(staging.iter().all(|v| *v == 0));
        assert!(cleared(&workspace));
    }
    Ok(())
}
fn inputs() -> Result<[Option<Input<'static>>; CAPACITY], Error> {
    let bits = bits(&[0x63; 200], 1600)?;
    let input = || Input::new(Algorithm::Shake128, bits, 2701).map(Some);
    Ok([input()?, input()?, input()?, input()?])
}
fn reusable(executor: &Executor<'_>) -> Result<(), Error> {
    let inputs = inputs()?;
    let mut outputs = core::array::from_fn(|_| vec![0; 338]);
    let mut stage = vec![0; 1352];
    let mut workspace = Workspace::new();
    let mut cancel = || false;
    executor.digest_secret(
        &inputs,
        destinations(&mut outputs),
        &mut workspace,
        &mut stage,
        &mut Control::new(100, &mut cancel),
    )?;
    assert!(cleared(&workspace));
    assert!(outputs.iter().all(|out| out.iter().all(|v| *v == 0)));
    Ok(())
}
#[test]
fn zero_output_still_frames_and_all_activity_masks_work() -> Result<(), Error> {
    for mask in 0_usize..16 {
        let empty = bits(&[], 0)?;
        let mut inputs: [Option<Input<'_>>; CAPACITY] = core::array::from_fn(|_| None);
        for (i, slot) in inputs.iter_mut().enumerate() {
            if mask & (1 << i) != 0 {
                *slot = Some(Input::new(Algorithm::Cshake128, empty, 0)?);
            }
        }
        let mut slots: [Vec<u8>; CAPACITY] = core::array::from_fn(|_| Vec::new());
        let outputs = slots
            .each_mut()
            .into_iter()
            .zip(&inputs)
            .map(|(slot, input)| input.as_ref().map(|_| slot.as_mut_slice()))
            .collect::<Vec<_>>();
        let outputs = outputs.try_into().map_err(|_| Error::Invariant)?;
        let mut stage = [0xa5; 17];
        let mut workspace = Workspace::new();
        let mut cancel = || false;
        let (owner, report) = Executor::portable().digest_secret(
            &inputs,
            outputs,
            &mut workspace,
            &mut stage,
            &mut Control::new(16, &mut cancel),
        )?;
        assert_eq!(report.scalar_permutations, u64::from(mask.count_ones()));
        for (i, input) in inputs.iter().enumerate() {
            assert_eq!(owner.output_bits(i), input.as_ref().map(|_| 0));
        }
        drop(owner);
        assert_eq!(stage, [0; 17]);
        assert!(cleared(&workspace));
    }
    Ok(())
}
#[test]
fn malformed_destinations_and_short_staging_clear_without_quarantine() -> Result<(), Error> {
    let executor = Executor::portable();
    let inputs = inputs()?;
    for index in 0..CAPACITY {
        for width in [0, 1, 337, 339] {
            for secret in [false, true] {
                let mut outputs = core::array::from_fn(|_| vec![0xa5; 338]);
                *outputs.get_mut(index).ok_or(Error::Invariant)? = vec![0xa5; width];
                let mut stage = vec![0xa7; 1400];
                let mut workspace = Workspace::new();
                let mut cancel = || false;
                let result = if secret {
                    executor
                        .digest_secret(
                            &inputs,
                            destinations(&mut outputs),
                            &mut workspace,
                            &mut stage,
                            &mut Control::new(100, &mut cancel),
                        )
                        .map(|_| ())
                } else {
                    executor
                        .digest_public(
                            &inputs,
                            destinations(&mut outputs),
                            &mut workspace,
                            &mut stage,
                            &mut Control::new(100, &mut cancel),
                            Sha3PublicDeclassification::acknowledge(),
                        )
                        .map(|_| ())
                };
                assert_eq!(result, Err(Error::InvalidDestination));
                assert!(
                    outputs
                        .iter()
                        .all(|out| out.iter().all(|v| *v == if secret { 0 } else { 0xa5 }))
                );
                assert!(stage.iter().all(|v| *v == 0));
                assert!(cleared(&workspace));
                reusable(&executor)?;
            }
        }
    }
    let mut outputs = core::array::from_fn(|_| vec![0xa5; 338]);
    let mut stage = [0xa7; 1];
    let mut workspace = Workspace::new();
    let mut cancel = || false;
    assert!(matches!(
        executor.digest_secret(
            &inputs,
            destinations(&mut outputs),
            &mut workspace,
            &mut stage,
            &mut Control::new(100, &mut cancel)
        ),
        Err(Error::InsufficientScratch)
    ));
    assert!(outputs.iter().all(|out| out.iter().all(|v| *v == 0)));
    assert_eq!(stage, [0]);
    assert!(cleared(&workspace));
    reusable(&executor)
}
fn failures(kernel: Option<Kernel>) -> Result<(), Error> {
    for boundary in 0..24 {
        for mode in 0..4 {
            for secret in [false, true] {
                let authority = kernel
                    .map(Authority::for_compiled_target)
                    .transpose()
                    .map_err(Error::Backend)?;
                let executor = if let Some(a) = &authority {
                    Executor::with_session(a.session().map_err(Error::Backend)?, Mode::Prefer, 1)?
                } else {
                    Executor::portable()
                };
                let inputs = inputs()?;
                let mut outputs = core::array::from_fn(|_| vec![0xa5; 338]);
                let mut stage = vec![0x72; 1400];
                let mut workspace = Workspace::new();
                let mut calls = 0_usize;
                let mut cancel = || {
                    let at = calls == boundary;
                    calls = calls.saturating_add(1);
                    if at && mode == 2 {
                        executor.quarantine();
                    }
                    if at && mode == 3 {
                        std::panic::resume_unwind(std::boxed::Box::new("cancel callback"));
                    }
                    at && mode == 1
                };
                let budget = if mode == 0 { boundary as u64 } else { 100 };
                let mut control = Control::new(budget, &mut cancel);
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    if secret {
                        executor
                            .digest_secret(
                                &inputs,
                                destinations(&mut outputs),
                                &mut workspace,
                                &mut stage,
                                &mut control,
                            )
                            .map(|_| ())
                    } else {
                        executor
                            .digest_public(
                                &inputs,
                                destinations(&mut outputs),
                                &mut workspace,
                                &mut stage,
                                &mut control,
                                Sha3PublicDeclassification::acknowledge(),
                            )
                            .map(|_| ())
                    }
                }));
                let failed = !matches!(result, Ok(Ok(())));
                if failed {
                    assert!(
                        outputs
                            .iter()
                            .all(|out| out.iter().all(|v| *v == if secret { 0 } else { 0xa5 }))
                    );
                }
                assert!(stage.iter().all(|v| *v == 0));
                assert!(cleared(&workspace));
                if failed && mode >= 2 {
                    assert!(executor.revoked.get());
                } else {
                    reusable(&executor)?;
                }
            }
        }
    }
    Ok(())
}
#[test]
fn all_work_cancel_revoke_and_unwind_boundaries() -> Result<(), Error> {
    failures(None)
}
#[test]
fn native_work_and_cancellation_boundaries() -> Result<(), Error> {
    for kernel in [Kernel::Avx2, Kernel::Neon] {
        if !kernel.compiled() {
            continue;
        }
        failures(Some(kernel))?;
    }
    Ok(())
}
#[test]
fn explicit_declassification_clears_source_and_preserves_failed_public_output() -> Result<(), Error>
{
    for wrong in [false, true] {
        let inputs = inputs()?;
        let executor = Executor::portable();
        let mut source = core::array::from_fn(|_| vec![0xa5; 338]);
        let mut public = core::array::from_fn(|_| vec![0x72; if wrong { 337 } else { 338 }]);
        let mut stage = vec![0x72; 1400];
        let mut workspace = Workspace::new();
        let mut cancel = || false;
        let (out, _) = executor.digest_secret(
            &inputs,
            destinations(&mut source),
            &mut workspace,
            &mut stage,
            &mut Control::new(100, &mut cancel),
        )?;
        let result = out.declassify(
            destinations(&mut public),
            Sha3PublicDeclassification::acknowledge(),
        );
        if wrong {
            assert_eq!(result, Err(Error::InvalidDestination));
            assert!(public.iter().flatten().all(|v| *v == 0x72));
        } else {
            result?;
            for (input, actual) in inputs.iter().flatten().zip(&public) {
                assert_eq!(*actual, oracle(input)?);
            }
        }
        assert!(source.iter().flatten().all(|v| *v == 0));
    }
    Ok(())
}
#[test]
fn workspace_destructor_clears_real_partial_state() -> Result<(), Error> {
    let mut s = Workspace::new();
    s.states.fill([0xa1; 200]);
    s.vector.fill([0xa2; 200]);
    s.starts.fill([0xa3; 8]);
    s.written.fill([0xa4; 8]);
    s.ready.fill(1);
    s.absorbing.fill(1);
    s.eligible.fill(1);
    for frame in &mut s.frames {
        frame.initialize(&Input::with_customization(
            Algorithm::Cshake128,
            bits(b"secret", 48)?,
            bits(b"name", 32)?,
            bits(b"custom", 48)?,
            19,
        )?)?;
    }
    s.scalar.sponge_lanes.fill(0xa5);
    s.scalar.padding_block.fill(0xa6);
    let before = DROPS.with(Cell::get);
    drop(s);
    assert_eq!(DROPS.with(Cell::get), before.saturating_add(1));
    Ok(())
}
