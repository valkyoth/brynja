//! Independent-slot ordinary SHA-224/256 batch acceptance.
#![cfg(feature = "batch-execution")]
use brynja_hash_sha2::{BitString, Sha256Digest, batch::*, sha224_bits, sha256_bits};

#[test]
fn bounded_batch_lifecycle_smoke() -> Result<(), String> {
    let bits = BitString::new(&[0xa0], 3).map_err(|e| format!("{e:?}"))?;
    let mut input = [None; 8];
    *input.first_mut().ok_or("slot")? = Some(Input::new(Algorithm::Sha256, bits));
    let mut output = [None; 8];
    let mut cancelled = || false;
    let mut control = Control::new(0, &mut cancelled);
    assert_eq!(
        Executor::portable().digest(PublicData::new(&input), &mut output, &mut control),
        Err(Error::WorkLimit)
    );
    assert_eq!(output, [None; 8]);
    let mut control = Control::new(1, &mut cancelled);
    let report = Executor::portable()
        .digest(PublicData::new(&input), &mut output, &mut control)
        .map_err(|e| format!("{e:?}"))?;
    assert_eq!(report.scalar_blocks, 1);
    assert_eq!(
        output.first().copied().flatten(),
        Some(oracle(Algorithm::Sha256, bits)?)
    );
    let before = output;
    let mut cancelled = || true;
    let mut control = Control::new(1, &mut cancelled);
    assert_eq!(
        Executor::portable().digest(PublicData::new(&input), &mut output, &mut control),
        Err(Error::Cancelled)
    );
    assert_eq!(output, before);
    Ok(())
}

fn oracle(algorithm: Algorithm, bits: BitString<'_>) -> Result<Digest, String> {
    match algorithm {
        Algorithm::Sha224 => sha224_bits(bits)
            .map(Digest::Sha224)
            .map_err(|e| format!("{e:?}")),
        Algorithm::Sha256 => sha256_bits(bits)
            .map(Digest::Sha256)
            .map_err(|e| format!("{e:?}")),
    }
}

fn campaign(executor: &Executor<'_>) -> Result<u64, String> {
    let mut calls = 0_u64;
    let lengths = [
        0_usize, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 511, 1024,
    ];
    for scenario in 0_u16..512 {
        let mask = if scenario < 256 { scenario } else { 255 };
        for tail in 1_u8..=8 {
            let mut storage = [[0_u8; 1024]; 8];
            for (lane, bytes) in storage.iter_mut().enumerate() {
                for (index, byte) in bytes.iter_mut().enumerate() {
                    *byte = index
                        .wrapping_mul(31)
                        .wrapping_add(lane.wrapping_mul(17))
                        .to_le_bytes()
                        .first()
                        .copied()
                        .ok_or("byte")?;
                }
            }
            let mut inputs = [None; 8];
            let mut expected = [None; 8];
            for (lane, ((bytes, input), output)) in storage
                .iter_mut()
                .zip(&mut inputs)
                .zip(&mut expected)
                .enumerate()
            {
                if mask & (1 << lane) == 0 {
                    continue;
                }
                let index = usize::from(scenario)
                    .wrapping_add(lane)
                    .wrapping_add(usize::from(tail))
                    .checked_rem(lengths.len())
                    .ok_or("modulus")?;
                let short = *lengths.get(index).ok_or("length")?;
                let length = if scenario < 256 {
                    short
                } else {
                    65_usize.checked_add(short.min(959)).ok_or("length")?
                };
                let bytes = bytes.get_mut(..length).ok_or("slice")?;
                if let Some(last) = bytes.last_mut() {
                    *last &= u8::MAX << 8_u8.saturating_sub(tail);
                }
                let bits = BitString::new(bytes, if length == 0 { 0 } else { tail })
                    .map_err(|e| format!("{e:?}"))?;
                let algorithm = if lane % 2 == 0 {
                    Algorithm::Sha224
                } else {
                    Algorithm::Sha256
                };
                let value = Input::new(algorithm, bits);
                *output = Some(oracle(algorithm, bits)?);
                *input = Some(value);
            }
            // Poison every active and inactive destination, including a wrong identity.
            let mut output = [Some(Digest::Sha256(Sha256Digest::from_bytes([0xa5; 32]))); 8];
            let mut cancel = || false;
            let mut control = Control::new(1000, &mut cancel);
            let report = executor
                .digest(PublicData::new(&inputs), &mut output, &mut control)
                .map_err(|e| format!("{e:?}"))?;
            assert_eq!(output, expected, "mask={mask} tail={tail}");
            assert_eq!(
                control.used(),
                report
                    .vector_blocks
                    .checked_add(report.scalar_blocks)
                    .ok_or("work")?
            );
            calls = calls.checked_add(report.vector_calls).ok_or("calls")?;
        }
    }
    Ok(calls)
}

#[test]
fn portable_masks_identities_and_bit_tails() -> Result<(), String> {
    assert_eq!(campaign(&Executor::portable())?, 0);
    Ok(())
}

#[test]
fn vector_masks_identities_and_bit_tails() -> Result<(), String> {
    let mut exercised = false;
    for kernel in [Kernel::Avx2, Kernel::Neon] {
        if !kernel.compiled() {
            continue;
        }
        let owner = Authority::for_compiled_target(kernel).map_err(|e| format!("{e:?}"))?;
        let executor = Executor::with_session(
            owner.session().map_err(|e| format!("{e:?}"))?,
            Mode::Prefer,
            1,
        )
        .map_err(|e| format!("{e:?}"))?;
        let calls = campaign(&executor)?;
        assert!(calls >= 2048);
        println!("SHA256_BATCH_VECTOR: {kernel:?}; calls={calls}");
        exercised = true;
    }
    if std::env::var_os("BRYNJA_REQUIRE_SHA256_BATCH").is_some() {
        assert!(exercised);
    }
    Ok(())
}

fn inputs(bytes: &[u8]) -> Result<[Option<Input<'_>>; 8], String> {
    let bits = BitString::new(bytes, if bytes.is_empty() { 0 } else { 8 })
        .map_err(|e| format!("{e:?}"))?;
    Ok([Some(Input::new(Algorithm::Sha256, bits)); 8])
}

#[test]
fn budget_cancellation_are_atomic_and_reusable() -> Result<(), String> {
    let input = inputs(&[0x37; 128])?;
    let sentinel = [Some(Digest::Sha256(Sha256Digest::from_bytes([0x63; 32]))); 8];
    for maximum in 0..24 {
        let executor = Executor::portable();
        let mut output = sentinel;
        let mut cancel = || false;
        let mut control = Control::new(maximum, &mut cancel);
        assert_eq!(
            executor.digest(PublicData::new(&input), &mut output, &mut control),
            Err(Error::WorkLimit)
        );
        assert_eq!(output, sentinel);
        assert_eq!(control.used(), maximum);
        let mut control = Control::new(24, &mut cancel);
        assert!(
            executor
                .digest(PublicData::new(&input), &mut output, &mut control)
                .is_ok()
        );
        assert_ne!(output, sentinel);
    }
    for stop in 0_u64..=24 {
        let mut remaining = stop;
        let mut cancel = || {
            let stop = remaining == 0;
            remaining = remaining.saturating_sub(1);
            stop
        };
        let mut output = sentinel;
        let mut control = Control::new(24, &mut cancel);
        assert_eq!(
            Executor::portable().digest(PublicData::new(&input), &mut output, &mut control),
            Err(Error::Cancelled)
        );
        assert_eq!(output, sentinel);
    }
    Ok(())
}

#[test]
fn vector_selection_revocation_and_work_accounting() -> Result<(), String> {
    for kernel in [Kernel::Avx2, Kernel::Neon] {
        if !kernel.compiled() {
            continue;
        }
        let owner = Authority::for_compiled_target(kernel).map_err(|e| format!("{e:?}"))?;
        let executor = Executor::with_session(
            owner.session().map_err(|e| format!("{e:?}"))?,
            Mode::Require,
            1,
        )
        .map_err(|e| format!("{e:?}"))?;
        let mut output = [None; 8];
        let mut cancel = || false;
        let mut control = Control::new(24, &mut cancel);
        assert_eq!(
            executor.digest(PublicData::new(&inputs(b"abc")?), &mut output, &mut control),
            Err(Error::IneligibleWorkload)
        );
        assert_eq!(control.used(), 0);
        for budget in 0..24 {
            let mut output = [None; 8];
            let mut control = Control::new(budget, &mut cancel);
            assert_eq!(
                executor.digest(
                    PublicData::new(&inputs(&[1; 128])?),
                    &mut output,
                    &mut control
                ),
                Err(Error::WorkLimit)
            );
            assert_eq!(output, [None; 8]);
            assert!(owner.is_healthy());
        }
        let mut control = Control::new(24, &mut cancel);
        let report = executor
            .digest(
                PublicData::new(&inputs(&[1; 128])?),
                &mut output,
                &mut control,
            )
            .map_err(|e| format!("{e:?}"))?;
        assert_eq!(report.vector_blocks, 16);
        assert_eq!(report.scalar_blocks, 8);
        assert_eq!(
            report.vector_calls,
            16 / u64::try_from(kernel.width()).map_err(|e| e.to_string())?
        );
        let saved = output;
        owner.quarantine();
        assert_eq!(
            executor.digest(
                PublicData::new(&inputs(&[1; 128])?),
                &mut output,
                &mut control
            ),
            Err(Error::Backend(BackendError::Quarantined))
        );
        assert_eq!(saved, output);
    }
    Ok(())
}

#[test]
fn callback_revocation_and_unwind_never_commit_outputs() -> Result<(), String> {
    for kernel in [Kernel::Avx2, Kernel::Neon] {
        if !kernel.compiled() {
            continue;
        }
        for stop in 0_u64..=24 {
            let owner = Authority::for_compiled_target(kernel).map_err(|e| format!("{e:?}"))?;
            let executor = Executor::with_session(
                owner.session().map_err(|e| format!("{e:?}"))?,
                Mode::Prefer,
                1,
            )
            .map_err(|e| format!("{e:?}"))?;
            let mut output = [None; 8];
            let mut calls = 0_u64;
            let mut cancel = || {
                if calls == stop {
                    owner.quarantine();
                }
                calls = calls.saturating_add(1);
                false
            };
            let mut control = Control::new(24, &mut cancel);
            let result = executor.digest(
                PublicData::new(&inputs(&[1; 128])?),
                &mut output,
                &mut control,
            );
            if result.is_err() {
                assert_eq!(output, [None; 8]);
                assert!(!owner.is_healthy());
            } else {
                assert!(owner.is_healthy());
            }
        }
        let owner = Authority::for_compiled_target(kernel).map_err(|e| format!("{e:?}"))?;
        let executor = Executor::with_session(
            owner.session().map_err(|e| format!("{e:?}"))?,
            Mode::Prefer,
            1,
        )
        .map_err(|e| format!("{e:?}"))?;
        let input = inputs(&[1; 128])?;
        let mut output = [None; 8];
        let mut cancel = || std::panic::resume_unwind(Box::new("test callback"));
        let mut control = Control::new(24, &mut cancel);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| executor.digest(
                PublicData::new(&input),
                &mut output,
                &mut control
            )))
            .is_err()
        );
        assert_eq!(output, [None; 8]);
        assert!(!owner.is_healthy());
    }
    Ok(())
}
