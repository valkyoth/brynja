//! Borrowed prefix composition must agree with actual concatenation.
#![cfg(feature = "hardened-execution")]
use brynja_legacy_md5::{
    BitString, Md5BackendHealth, Md5BatchControl,
    hardened_execution::{Executor, Mode, in_place::Workspace},
};
type Result = core::result::Result<(), Box<dyn std::error::Error>>;

fn executor() -> core::result::Result<Executor, Box<dyn std::error::Error>> {
    let result = Executor::for_compiled_target(Mode::Prefer)?;
    if std::env::var_os("BRYNJA_REQUIRE_HARDENED_MD5").is_some() {
        assert!(result.backend().is_some(), "native SIMD required");
    }
    Ok(result)
}

#[test]
fn bounded_portable_prefix_cleanup() -> Result {
    let executor = Executor::portable();
    let mut workspace = Workspace::new(&executor);
    let prefixes = [[0x36; 64]; 8];
    let mut inputs = [None; 8];
    *inputs.get_mut(3).ok_or("slot")? = Some(BitString::new(&[0x80], 1).map_err(|_| "bits")?);
    let mut joined = [0x36; 65];
    *joined.last_mut().ok_or("tail")? = 0x80;
    let expected = brynja_legacy_md5::md5_bits(BitString::new(&joined, 1).map_err(|_| "bits")?)?;
    for budget in 0..=2 {
        let mut output = [[0xa5; 16]; 8];
        let result = workspace.with(|batch| {
            batch.digest_prefixed_secret(
                &prefixes,
                &inputs,
                &mut output,
                &mut Md5BatchControl::new(budget),
            )
        })?;
        if budget < 2 {
            assert!(result.is_err());
            drop(result);
        } else {
            let (secret, report) = result?;
            assert_eq!(secret.expose().get(48..64), Some(expected.as_slice()));
            assert_eq!(report.work.active_lanes, 1);
            assert_eq!(report.work.scalar_blocks, 2);
            assert_eq!(report.work.vector_blocks, 0);
            drop(secret);
        }
        assert_eq!(output, [[0; 16]; 8]);
        assert_eq!(executor.health(), Md5BackendHealth::Healthy);
    }
    Ok(())
}

#[test]
fn every_mask_bit_tail_and_block_boundary_matches_concatenation() -> Result {
    let executor = executor()?;
    let mut workspace = Workspace::new(&executor);
    let prefixes = [1u8, 2, 3, 4, 5, 6, 7, 8].map(|byte| [byte; 64]);
    let mut vector_total = 0;
    for mask in 0..=255u16 {
        for valid in 1..=8 {
            let mut bytes = [[0xab; 193]; 8];
            let mut inputs = [None; 8];
            let mut expected = [[0; 16]; 8];
            let mut work = 0;
            for (lane, ((input, data), expected)) in inputs
                .iter_mut()
                .zip(&mut bytes)
                .zip(&mut expected)
                .enumerate()
            {
                if mask & (1 << lane) == 0 {
                    continue;
                }
                let length = *[0, 1, 55, 56, 63, 64, 128, 193]
                    .get((lane + usize::from(valid)) % 8)
                    .ok_or("length index")?;
                let tail = data.get_mut(..length).ok_or("length")?;
                if let Some(last) = tail.last_mut() {
                    *last &= 255 << (8 - valid);
                }
                *input = Some(
                    BitString::new(tail, if length == 0 { 0 } else { valid })
                        .map_err(|_| "bits")?,
                );
                let mut joined = prefixes.get(lane).ok_or("prefix index")?.to_vec();
                joined.extend_from_slice(tail);
                *expected = brynja_legacy_md5::md5_bits(
                    BitString::new(&joined, if length == 0 { 8 } else { valid })
                        .map_err(|_| "bits")?,
                )?;
                let bits = input.ok_or("input")?.bit_len();
                work += 1 + bits / 512 + if bits % 512 < 448 { 1 } else { 2 };
            }
            let mut output = [[0xa5; 16]; 8];
            let mut control = Md5BatchControl::new(work);
            let (secret, report) = workspace.with(|batch| {
                batch.digest_prefixed_secret(&prefixes, &inputs, &mut output, &mut control)
            })??;
            assert_eq!(secret.expose(), expected.as_flattened());
            assert_eq!(report.work.active_lanes, mask.count_ones() as usize);
            assert_eq!(report.work.scalar_blocks + report.work.vector_blocks, work);
            assert_eq!(control.remaining(), 0);
            let width = executor.backend().map_or(8, |b| b.lane_width());
            let expected_vector = if executor.backend().is_some() {
                inputs
                    .chunks(width)
                    .filter(|g| g.iter().all(Option::is_some))
                    .map(|g| {
                        width
                            * (1 + g
                                .iter()
                                .map(|v| v.map_or(0, |b| b.bit_len() / 512))
                                .min()
                                .unwrap_or(0))
                    })
                    .sum()
            } else {
                0
            };
            assert_eq!(report.work.vector_blocks, expected_vector);
            vector_total += report.work.vector_blocks;
            drop(secret);
            assert_eq!(output, [[0; 16]; 8]);
        }
    }
    if executor.backend().is_some() {
        assert!(vector_total > 0);
    }
    Ok(())
}

#[test]
fn prefix_budget_rejection_clears_output_and_preserves_executor() -> Result {
    let executor = executor()?;
    let mut workspace = Workspace::new(&executor);
    let prefixes = [[0x36; 64]; 8];
    let data = [0x73; 128];
    let inputs = [Some(BitString::new(&data, 8).map_err(|_| "bits")?); 8];
    for budget in 0..32 {
        let mut output = [[0xa5; 16]; 8];
        assert!(
            workspace
                .with(|batch| batch.digest_prefixed_secret(
                    &prefixes,
                    &inputs,
                    &mut output,
                    &mut Md5BatchControl::new(budget)
                ))?
                .is_err()
        );
        assert_eq!(output, [[0; 16]; 8]);
        assert_eq!(executor.health(), Md5BackendHealth::Healthy);
        let (secret, report) = workspace.with(|batch| {
            batch.digest_prefixed_secret(
                &prefixes,
                &inputs,
                &mut output,
                &mut Md5BatchControl::new(32),
            )
        })??;
        assert_eq!(report.work.scalar_blocks + report.work.vector_blocks, 32);
        drop(secret);
        assert_eq!(output, [[0; 16]; 8]);
    }
    Ok(())
}

#[test]
fn prefix_cancel_revoke_and_unwind_at_every_charge() -> Result {
    let prefixes = [[0x5c; 64]; 8];
    let data = [0x47; 128];
    let inputs = [Some(BitString::new(&data, 8).map_err(|_| "bits")?); 8];
    let reference = executor()?;
    let mut count = 0;
    let mut callback = || {
        count += 1;
        false
    };
    let mut workspace = Workspace::new(&reference);
    let mut output = [[0xa5; 16]; 8];
    drop(workspace.with(|batch| {
        batch.digest_prefixed_secret(
            &prefixes,
            &inputs,
            &mut output,
            &mut Md5BatchControl::with_cancellation(32, &mut callback),
        )
    })??);
    assert!(count > 0);
    for boundary in 1..=count {
        for mode in 0..3 {
            let executor = executor()?;
            let mut workspace = Workspace::new(&executor);
            output.fill([0xa5; 16]);
            let mut calls = 0;
            let mut callback = || {
                calls += 1;
                if calls != boundary {
                    return false;
                }
                match mode {
                    0 => true,
                    1 => {
                        executor.quarantine();
                        false
                    }
                    _ => std::panic::resume_unwind(Box::new("prefix unwind")),
                }
            };
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                workspace.with(|batch| {
                    batch
                        .digest_prefixed_secret(
                            &prefixes,
                            &inputs,
                            &mut output,
                            &mut Md5BatchControl::with_cancellation(32, &mut callback),
                        )
                        .map(|(secret, report)| {
                            drop(secret);
                            report
                        })
                })
            }));
            match mode {
                0 | 1 => assert!(result.map_err(|_| "unexpected panic")??.is_err()),
                _ => assert!(result.is_err()),
            }
            assert_eq!(output, [[0; 16]; 8]);
            assert_eq!(
                executor.health(),
                if mode == 0 {
                    Md5BackendHealth::Healthy
                } else {
                    Md5BackendHealth::Quarantined
                }
            );
        }
    }
    Ok(())
}
