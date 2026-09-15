use super::*;

fn campaign(executor: &Executor<'_>, width: Option<usize>) -> Result<u64, Error> {
    let mut comparisons = 0_u64;
    for length in [
        0_usize, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 255, 256, 513,
    ] {
        for tail in 1..=8 {
            let mut bytes = [[0_u8; 600]; CAPACITY];
            let mut inputs = core::array::from_fn(|_| None);
            for (lane, (buffer, input)) in bytes.iter_mut().zip(&mut inputs).enumerate() {
                // Mix exact identities and unequal message lengths; lane-specific
                // contents catch both transposition and stale staging reuse.
                let size = length.checked_add(lane).ok_or(Error::Invariant)?;
                let buffer = buffer.get_mut(..size).ok_or(Error::Invariant)?;
                for (offset, byte) in buffer.iter_mut().enumerate() {
                    *byte = u8::try_from(offset % 256)
                        .map_err(|_| Error::Invariant)?
                        .wrapping_mul(71)
                        .wrapping_add(
                            u8::try_from(lane)
                                .map_err(|_| Error::Invariant)?
                                .wrapping_mul(23),
                        );
                }
                if let Some(last) = buffer.last_mut() {
                    *last &= u8::MAX << 8_u8.saturating_sub(tail);
                }
                let algorithm = if lane % 2 == 0 {
                    Algorithm::Sha224
                } else {
                    Algorithm::Sha256
                };
                *input = Some(Input::new(algorithm, bits(buffer, tail)?));
            }
            let mut storage = [[0xa5; 32]; CAPACITY];
            let mut workspace = Workspace::new();
            poison(&mut workspace);
            let mut cancel = || false;
            let mut control = Control::new(1000, &mut cancel);
            let report = executor.digest_public(
                &inputs,
                destinations(&mut storage, &inputs),
                &mut workspace,
                &mut control,
                PublicDeclassification::acknowledge(),
            )?;
            assert_eq!(
                report.vector_blocks.checked_add(report.scalar_blocks),
                Some(control.used())
            );
            if let Some(width) = width {
                if length >= 65 {
                    assert!(report.vector_calls > 0);
                }
                assert_eq!(
                    Some(report.vector_blocks),
                    report.vector_calls.checked_mul(width as u64)
                );
            } else {
                assert_eq!(report.vector_calls, 0);
            }
            for (out, input) in storage.iter().zip(inputs.iter().flatten()) {
                let expected = oracle(input)?;
                let size = input.algorithm.output_bytes();
                assert_eq!(
                    out.get(..size).ok_or(Error::Invariant)?,
                    expected.get(..size).ok_or(Error::Invariant)?
                );
                assert!(
                    out.get(size..)
                        .ok_or(Error::Invariant)?
                        .iter()
                        .all(|byte| *byte == 0xa5)
                );
                comparisons = comparisons.checked_add(1).ok_or(Error::Invariant)?;
            }
            cleared(&workspace);
        }
    }
    Ok(comparisons)
}
#[test]
fn portable_all_bit_tails_padding_boundaries_and_mixed_identities() -> Result<(), Error> {
    assert_eq!(campaign(&Executor::portable(), None)?, 960);
    Ok(())
}
#[test]
fn sparse_empty_and_inactive_slots_are_distinct() -> Result<(), Error> {
    for mask in 0_u16..256 {
        let empty = bits(&[], 0)?;
        let inputs = core::array::from_fn(|index| {
            (mask & (1 << index) != 0).then(|| Input::new(Algorithm::Sha256, empty))
        });
        let mut storage = [[0xa5; 32]; CAPACITY];
        let mut workspace = Workspace::new();
        let mut cancel = || false;
        let mut control = Control::new(8, &mut cancel);
        let (output, report) = Executor::portable().digest_secret(
            &inputs,
            destinations(&mut storage, &inputs),
            &mut workspace,
            &mut control,
        )?;
        assert_eq!(report.scalar_blocks, u64::from(mask.count_ones()));
        for (index, input) in inputs.iter().enumerate() {
            if let Some(input) = input {
                assert_eq!(output.expose(index), Some(oracle(input)?.as_slice()));
            } else {
                assert!(output.expose(index).is_none());
            }
        }
        assert!(output.expose(usize::MAX).is_none());
        drop(output);
        for (out, input) in storage.iter().zip(&inputs) {
            assert_eq!(*out, [if input.is_some() { 0 } else { 0xa5 }; 32]);
        }
        cleared(&workspace);
    }
    Ok(())
}
#[test]
fn native_mixed_lanes_match_portable_and_required_route_is_real() -> Result<(), Error> {
    let mut executed = 0;
    for kernel in [Kernel::Avx2, Kernel::Neon] {
        if !kernel.compiled() {
            continue;
        }
        let authority = Authority::for_compiled_target(kernel).map_err(Error::Backend)?;
        let executor = Executor::with_session(
            authority.session().map_err(Error::Backend)?,
            Mode::Prefer,
            1,
        )?;
        assert_eq!(campaign(&executor, Some(kernel.width()))?, 960);
        let required = Executor::with_session(
            authority.session().map_err(Error::Backend)?,
            Mode::Require,
            1,
        )?;
        reusable(&required)?;
        assert!(
            authority
                .session()
                .map_err(Error::Backend)?
                .completed_vector_calls()
                > 0
        );
        executed += 1;
    }
    if std::env::var_os("BRYNJA_REQUIRE_SHA256_HARDENED_BATCH").is_some() {
        assert_eq!(executed, 1);
    }
    Ok(())
}
#[test]
fn required_ineligible_work_is_atomic_and_reusable() -> Result<(), Error> {
    for kernel in [Kernel::Avx2, Kernel::Neon] {
        if !kernel.compiled() {
            continue;
        }
        let authority = Authority::for_compiled_target(kernel).map_err(Error::Backend)?;
        for mode in [Mode::Prefer, Mode::Require] {
            let executor =
                Executor::with_session(authority.session().map_err(Error::Backend)?, mode, 2)?;
            let b = bits(&[0x5a; 64], 8)?;
            let inputs = core::array::from_fn(|_| Some(Input::new(Algorithm::Sha256, b)));
            let mut storage = [[0xa5; 32]; CAPACITY];
            let mut workspace = Workspace::new();
            let mut cancel = || false;
            let mut control = Control::new(16, &mut cancel);
            let result = executor.digest_public(
                &inputs,
                destinations(&mut storage, &inputs),
                &mut workspace,
                &mut control,
                PublicDeclassification::acknowledge(),
            );
            if mode == Mode::Require {
                assert_eq!(result, Err(Error::IneligibleWorkload));
                assert_eq!(storage, [[0xa5; 32]; CAPACITY]);
                assert_eq!(control.used(), 0);
            } else {
                assert_eq!(result?.vector_calls, 0);
                assert_eq!(control.used(), 16);
            }
            cleared(&workspace);
            reusable(&executor)?;
        }
    }
    Ok(())
}
