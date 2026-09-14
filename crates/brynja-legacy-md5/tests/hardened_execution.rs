//! Distinct secret SIMD owners, exact route/work and all-output lifecycle tests.
#![cfg(feature = "hardened-execution")]
use brynja_legacy_md5::{
    BitString, Md5BackendHealth, Md5BatchControl, PublicDeclassification,
    hardened_execution::{Executor, Mode},
};
type Result = core::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn bounded_portable_cleanup_smoke() -> Result {
    let executor = Executor::portable();
    let mut output = [[0xa5; 16]; 8];
    let mut inputs = [None; 8];
    inputs[0] = Some(BitString::new(b"abc", 8).map_err(|_| "bits")?);
    let (owned, report) =
        executor
            .batch()
            .digest_secret(&inputs, &mut output, &mut Md5BatchControl::new(1))?;
    assert_eq!(
        owned.expose().get(..16),
        Some(brynja_legacy_md5::md5(b"abc")?.as_slice())
    );
    assert_eq!(report.work.vector_blocks, 0);
    drop(owned);
    assert_eq!(output, [[0; 16]; 8]);
    let executor = Executor::portable();
    output.fill([0xa5; 16]);
    let mut callback = || std::panic::resume_unwind(Box::new("bounded unwind"));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        executor
            .batch()
            .digest_secret(
                &inputs,
                &mut output,
                &mut Md5BatchControl::with_cancellation(1, &mut callback),
            )
            .map(|(owner, report)| {
                drop(owner);
                report
            })
    }));
    assert!(result.is_err());
    assert_eq!(output, [[0; 16]; 8]);
    assert_eq!(executor.health(), Md5BackendHealth::Quarantined);
    Ok(())
}

fn executor() -> core::result::Result<Executor, Box<dyn std::error::Error>> {
    let executor = Executor::for_compiled_target(Mode::Prefer)?;
    if std::env::var_os("BRYNJA_REQUIRE_HARDENED_MD5").is_some() {
        assert!(executor.backend().is_some(), "actual SIMD required");
    }
    Ok(executor)
}

#[test]
fn all_masks_bits_and_unequal_lengths_match_portable_with_exact_work() -> Result {
    let executor = executor()?;
    let mut vector_total = 0;
    for mask in 0..256u16 {
        for valid in 1..=8 {
            let mut data: [[u8; 257]; 8] = core::array::from_fn(|lane| {
                core::array::from_fn(|i| u8::try_from((lane * 37 + i * 13) % 256).unwrap_or(0))
            });
            let mut inputs = [None; 8];
            for (lane, (input, bytes)) in inputs.iter_mut().zip(data.iter_mut()).enumerate() {
                if mask & (1 << lane) != 0 {
                    let lengths = if mask == 255 {
                        [65, 128, 129, 200, 256, 257, 128, 200]
                    } else {
                        [0, 55, 56, 63, 64, 65, 128, 257]
                    };
                    let length = *lengths
                        .get((lane + usize::from(valid)) % 8)
                        .ok_or("length")?;
                    let bytes = bytes.get_mut(..length).ok_or("slice")?;
                    if let Some(last) = bytes.last_mut() {
                        *last &= u8::MAX << (8 - valid);
                    }
                    *input = Some(
                        BitString::new(bytes, if length == 0 { 0 } else { valid })
                            .map_err(|_| "bits")?,
                    );
                }
            }
            let mut expected = [[0; 16]; 8];
            for (dst, input) in expected.iter_mut().zip(inputs) {
                if let Some(input) = input {
                    *dst = brynja_legacy_md5::md5_bits(input)?;
                }
            }
            let mut public = expected.map(|lane| lane.map(|b| !b));
            let report = executor.batch().digest_public(
                &inputs,
                &mut public,
                &mut Md5BatchControl::new(128),
                PublicDeclassification::acknowledge(),
            )?;
            assert_eq!(public, expected);
            let mut secret = expected.map(|lane| lane.map(|b| !b));
            let mut control = Md5BatchControl::new(128);
            let (owned, secret_report) =
                executor
                    .batch()
                    .digest_secret(&inputs, &mut secret, &mut control)?;
            assert_eq!(owned.expose(), expected.as_flattened());
            assert_eq!(report, secret_report);
            drop(owned);
            assert_eq!(secret, [[0; 16]; 8]);
            let wanted_vector = executor.backend().map_or(0, |b| {
                inputs
                    .chunks(b.lane_width())
                    .map(|g| {
                        g.iter()
                            .map(|i| i.map_or(0, |b| b.bit_len() / 512))
                            .min()
                            .unwrap_or(0)
                            * b.lane_width()
                    })
                    .sum()
            });
            let total: usize = inputs
                .iter()
                .flatten()
                .map(|i| (i.bit_len() + 65).div_ceil(512))
                .sum();
            assert_eq!(report.work.vector_blocks, wanted_vector);
            assert_eq!(report.work.scalar_blocks, total - wanted_vector);
            assert_eq!(report.work.active_lanes, inputs.iter().flatten().count());
            assert_eq!(control.remaining(), 128 - total);
            assert_eq!(
                report.backend,
                executor.backend().filter(|_| wanted_vector > 0)
            );
            assert_eq!(
                report.vector_width,
                report.backend.map_or(0, |b| b.lane_width())
            );
            vector_total += wanted_vector;
        }
    }
    if let Some(backend) = executor.backend() {
        assert!(vector_total > 0);
        println!(
            "MD5_HARDENED: {}; cases=2048; actual SIMD",
            backend.as_str()
        );
    }
    Ok(())
}

#[test]
fn every_work_failure_clears_secret_and_preserves_public() -> Result {
    let bytes = [0xa5; 128];
    let inputs = [Some(BitString::new(&bytes, 8).map_err(|_| "bits")?); 8];
    for budget in 0..24 {
        for secret in [false, true] {
            let executor = executor()?;
            let mut output = [[0xa5; 16]; 8];
            let mut control = Md5BatchControl::new(budget);
            if secret {
                assert!(
                    executor
                        .batch()
                        .digest_secret(&inputs, &mut output, &mut control)
                        .is_err()
                );
                assert_eq!(output, [[0; 16]; 8]);
            } else {
                assert!(
                    executor
                        .batch()
                        .digest_public(
                            &inputs,
                            &mut output,
                            &mut control,
                            PublicDeclassification::acknowledge()
                        )
                        .is_err()
                );
                assert_eq!(output, [[0xa5; 16]; 8]);
            }
            assert_eq!(executor.health(), Md5BackendHealth::Quarantined);
        }
    }
    let executor = executor()?;
    let mut output = [[0xa5; 16]; 8];
    let report = executor.batch().digest_public(
        &inputs,
        &mut output,
        &mut Md5BatchControl::new(24),
        PublicDeclassification::acknowledge(),
    )?;
    assert_eq!(output, [brynja_legacy_md5::md5(&bytes)?; 8]);
    assert_eq!(report.work.scalar_blocks + report.work.vector_blocks, 24);
    Ok(())
}

#[test]
fn cancellation_revocation_and_unwind_at_every_boundary() -> Result {
    let bytes = [0x7e; 128];
    let inputs = [Some(BitString::new(&bytes, 8).map_err(|_| "bits")?); 8];
    // Discover the complete successful route's callback count so adding a
    // boundary cannot silently escape this campaign's former fixed limit.
    let baseline = executor()?;
    let mut boundaries = 0;
    let mut count = || {
        boundaries += 1;
        false
    };
    let mut baseline_output = [[0xa5; 16]; 8];
    baseline.batch().digest_public(
        &inputs,
        &mut baseline_output,
        &mut Md5BatchControl::with_cancellation(128, &mut count),
        PublicDeclassification::acknowledge(),
    )?;
    assert!(boundaries > 0);
    assert_eq!(baseline_output, [brynja_legacy_md5::md5(&bytes)?; 8]);
    for action in 0..3 {
        for at in 0..=boundaries {
            for secret in [false, true] {
                let executor = executor()?;
                let mut calls = 0;
                let mut triggered = false;
                let mut callback = || {
                    let trigger = calls == at;
                    calls += 1;
                    if trigger {
                        triggered = true;
                        match action {
                            0 => return true,
                            1 => executor.quarantine(),
                            _ => std::panic::resume_unwind(Box::new("test callback unwind")),
                        }
                    }
                    false
                };
                let mut output = [[0xa5; 16]; 8];
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut control = Md5BatchControl::with_cancellation(128, &mut callback);
                    if secret {
                        executor
                            .batch()
                            .digest_secret(&inputs, &mut output, &mut control)
                            .map(|(owned, report)| {
                                drop(owned);
                                report
                            })
                    } else {
                        executor.batch().digest_public(
                            &inputs,
                            &mut output,
                            &mut control,
                            PublicDeclassification::acknowledge(),
                        )
                    }
                }));
                if triggered {
                    assert!(!matches!(result, Ok(Ok(_))));
                    assert_eq!(output, [[if secret { 0 } else { 0xa5 }; 16]; 8]);
                    assert_eq!(executor.health(), Md5BackendHealth::Quarantined);
                } else {
                    assert!(matches!(result, Ok(Ok(_))));
                }
            }
        }
    }
    Ok(())
}

#[test]
fn required_empty_work_and_explicit_revocation_fail_before_commit() -> Result {
    if let Ok(executor) = Executor::for_compiled_target(Mode::Require) {
        let mut output = [[0xa5; 16]; 8];
        let mut control = Md5BatchControl::new(0);
        assert!(
            executor
                .batch()
                .digest_secret(&[None; 8], &mut output, &mut control)
                .is_err()
        );
        assert_eq!(output, [[0; 16]; 8]);
        assert_eq!(control.remaining(), 0);
    }
    let executor = Executor::portable();
    let batch = executor.batch();
    executor.quarantine();
    let mut output = [[0xa5; 16]; 8];
    assert!(
        batch
            .digest_secret(&[None; 8], &mut output, &mut Md5BatchControl::new(0))
            .is_err()
    );
    assert_eq!(output, [[0; 16]; 8]);
    Ok(())
}
