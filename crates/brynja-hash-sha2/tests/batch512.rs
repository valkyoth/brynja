//! Independent-slot ordinary SHA-384/512 batch acceptance.
#![cfg(feature = "batch512-execution")]
use brynja_hash_sha2::{BitString, Sha512Digest, batch512::*, sha384_bits, sha512_bits};

mod batch512_general;

#[test]
fn bounded_batch_lifecycle_smoke() -> Result<(), String> {
    let bits = BitString::new(&[0xa0], 3).map_err(|e| format!("{e:?}"))?;
    let mut input = [None; 4];
    *input.first_mut().ok_or("slot")? = Some(Input::new(Algorithm::Sha512, bits));
    let mut output = [None; 4];
    let mut cancelled = || false;
    let mut control = Control::new(0, &mut cancelled);
    assert_eq!(
        Executor::portable().digest(PublicData::new(&input), &mut output, &mut control),
        Err(Error::WorkLimit)
    );
    assert_eq!(output, [None; 4]);
    let mut control = Control::new(1, &mut cancelled);
    let report = Executor::portable()
        .digest(PublicData::new(&input), &mut output, &mut control)
        .map_err(|e| format!("{e:?}"))?;
    assert_eq!(report.scalar_blocks, 1);
    assert_eq!(
        output.first().copied().flatten(),
        Some(oracle(Algorithm::Sha512, bits)?)
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
    use brynja_hash_sha2::{sha512_224_bits, sha512_256_bits, sha512_t_bits};
    match algorithm {
        Algorithm::Sha384 => sha384_bits(bits)
            .map(Digest::Sha384)
            .map_err(|e| format!("{e:?}")),
        Algorithm::Sha512 => sha512_bits(bits)
            .map(Digest::Sha512)
            .map_err(|e| format!("{e:?}")),
        Algorithm::Sha512_224 => sha512_224_bits(bits)
            .map(Digest::Sha512_224)
            .map_err(|e| format!("{e:?}")),
        Algorithm::Sha512_256 => sha512_256_bits(bits)
            .map(Digest::Sha512_256)
            .map_err(|e| format!("{e:?}")),
        Algorithm::Sha512T(t) => sha512_t_bits(t, bits)
            .map(Digest::Sha512T)
            .map_err(|e| format!("{e:?}")),
    }
}

fn campaign(executor: &Executor<'_>) -> Result<u64, String> {
    let mut calls = 0_u64;
    let lengths = [
        0_usize, 1, 111, 112, 119, 120, 127, 128, 129, 239, 240, 255, 256, 257, 1024,
    ];
    for scenario in 0_u16..512 {
        let mask = if scenario < 256 { scenario } else { 255 };
        for tail in 1_u8..=8 {
            let mut storage = [[0_u8; 1024]; 4];
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
            let mut inputs = [None; 4];
            let mut expected = [None; 4];
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
                    129_usize.checked_add(short.min(895)).ok_or("length")?
                };
                let bytes = bytes.get_mut(..length).ok_or("slice")?;
                if let Some(last) = bytes.last_mut() {
                    *last &= u8::MAX << 8_u8.saturating_sub(tail);
                }
                let bits = BitString::new(bytes, if length == 0 { 0 } else { tail })
                    .map_err(|e| format!("{e:?}"))?;
                let algorithm = if lane % 2 == 0 {
                    Algorithm::Sha384
                } else {
                    Algorithm::Sha512
                };
                let value = Input::new(algorithm, bits);
                *output = Some(oracle(algorithm, bits)?);
                *input = Some(value);
            }
            // Poison every active and inactive destination, including a wrong identity.
            let mut output = [Some(Digest::Sha512(Sha512Digest::from_bytes([0xa5; 64]))); 4];
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
        println!("SHA512_BATCH_VECTOR: {kernel:?}; calls={calls}");
        exercised = true;
    }
    if std::env::var_os("BRYNJA_REQUIRE_SHA512_BATCH").is_some() {
        assert!(exercised);
    }
    Ok(())
}

fn inputs(bytes: &[u8]) -> Result<[Option<Input<'_>>; 4], String> {
    let bits = BitString::new(bytes, if bytes.is_empty() { 0 } else { 8 })
        .map_err(|e| format!("{e:?}"))?;
    Ok([Some(Input::new(Algorithm::Sha512, bits)); 4])
}

#[test]
fn budget_cancellation_are_atomic_and_reusable() -> Result<(), String> {
    let input = inputs(&[0x37; 256])?;
    let sentinel = [Some(Digest::Sha512(Sha512Digest::from_bytes([0x63; 64]))); 4];
    for maximum in 0..12 {
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
        let mut control = Control::new(12, &mut cancel);
        assert!(
            executor
                .digest(PublicData::new(&input), &mut output, &mut control)
                .is_ok()
        );
        assert_ne!(output, sentinel);
    }
    for stop in 0_u64..=12 {
        let mut remaining = stop;
        let mut cancel = || {
            let stop = remaining == 0;
            remaining = remaining.saturating_sub(1);
            stop
        };
        let mut output = sentinel;
        let mut control = Control::new(12, &mut cancel);
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
        let mut output = [None; 4];
        let mut cancel = || false;
        let mut control = Control::new(12, &mut cancel);
        assert_eq!(
            executor.digest(PublicData::new(&inputs(b"abc")?), &mut output, &mut control),
            Err(Error::IneligibleWorkload)
        );
        assert_eq!(control.used(), 0);
        for budget in 0..12 {
            let mut output = [None; 4];
            let mut control = Control::new(budget, &mut cancel);
            assert_eq!(
                executor.digest(
                    PublicData::new(&inputs(&[1; 256])?),
                    &mut output,
                    &mut control
                ),
                Err(Error::WorkLimit)
            );
            assert_eq!(output, [None; 4]);
            assert!(owner.is_healthy());
        }
        let mut control = Control::new(12, &mut cancel);
        let report = executor
            .digest(
                PublicData::new(&inputs(&[1; 256])?),
                &mut output,
                &mut control,
            )
            .map_err(|e| format!("{e:?}"))?;
        assert_eq!(report.vector_blocks, 8);
        assert_eq!(report.scalar_blocks, 4);
        assert_eq!(
            report.vector_calls,
            8 / u64::try_from(kernel.width()).map_err(|e| e.to_string())?
        );
        let saved = output;
        owner.quarantine();
        assert_eq!(
            executor.digest(
                PublicData::new(&inputs(&[1; 256])?),
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
        for stop in 0_u64..=12 {
            let owner = Authority::for_compiled_target(kernel).map_err(|e| format!("{e:?}"))?;
            let executor = Executor::with_session(
                owner.session().map_err(|e| format!("{e:?}"))?,
                Mode::Prefer,
                1,
            )
            .map_err(|e| format!("{e:?}"))?;
            let mut output = [None; 4];
            let mut calls = 0_u64;
            let mut cancel = || {
                if calls == stop {
                    owner.quarantine();
                }
                calls = calls.saturating_add(1);
                false
            };
            let mut control = Control::new(12, &mut cancel);
            let result = executor.digest(
                PublicData::new(&inputs(&[1; 256])?),
                &mut output,
                &mut control,
            );
            if result.is_err() {
                assert_eq!(output, [None; 4]);
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
        let input = inputs(&[1; 256])?;
        let mut output = [None; 4];
        let mut cancel = || std::panic::resume_unwind(Box::new("test callback"));
        let mut control = Control::new(12, &mut cancel);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| executor.digest(
                PublicData::new(&input),
                &mut output,
                &mut control
            )))
            .is_err()
        );
        assert_eq!(output, [None; 4]);
        assert!(!owner.is_healthy());
    }
    Ok(())
}
