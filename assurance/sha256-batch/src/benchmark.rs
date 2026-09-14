use brynja_hash_sha2::{BitString, batch::*, execution};
use std::{hint::black_box, time::Instant};

pub fn run(executor: &Executor<'_>) -> Result<(), String> {
    for algorithm in [Algorithm::Sha224, Algorithm::Sha256] {
        for length in [64_usize, 128, 1024, 16384] {
            let storage: [Vec<u8>; 8] = core::array::from_fn(|lane| {
                (0..length)
                    .map(|i| i.wrapping_add(lane).to_le_bytes()[0])
                    .collect()
            });
            let mut inputs = [None; 8];
            for (input, bytes) in inputs.iter_mut().zip(&storage) {
                *input = Some(Input::new(
                    algorithm,
                    BitString::new(bytes, 8).map_err(|e| format!("{e:?}"))?,
                ));
            }
            let mut output = [None; 8];
            let mut cancel = || false;
            let mut control = Control::new(u64::MAX, &mut cancel);
            let report = executor
                .digest(PublicData::new(&inputs), &mut output, &mut control)
                .map_err(|e| format!("{e:?}"))?;
            let mut expected = [None; 8];
            Executor::portable()
                .digest(PublicData::new(&inputs), &mut expected, &mut control)
                .map_err(|e| format!("{e:?}"))?;
            if output != expected {
                return Err("benchmark output mismatch".into());
            }
            let iterations = if length <= 1024 { 64 } else { 8 };
            let portable = measure(
                || {
                    Executor::portable()
                        .digest(
                            PublicData::new(black_box(&inputs)),
                            &mut output,
                            &mut control,
                        )
                        .map_err(|e| format!("{e:?}"))?;
                    black_box(output);
                    Ok(())
                },
                iterations,
            )?;
            let selected = measure(
                || {
                    executor
                        .digest(
                            PublicData::new(black_box(&inputs)),
                            &mut output,
                            &mut control,
                        )
                        .map_err(|e| format!("{e:?}"))?;
                    black_box(output);
                    Ok(())
                },
                iterations,
            )?;
            let mut dedicated = None;
            for kernel in [execution::Kernel::X86Sha256, execution::Kernel::ArmSha256] {
                if kernel.check_compiled_target().is_err() {
                    continue;
                }
                let owner = execution::StaticSelection::new(kernel, execution::Mode::Require)
                    .map_err(|e| format!("{e:?}"))?;
                dedicated = Some(measure(
                    || {
                        for bytes in &storage {
                            match algorithm {
                                Algorithm::Sha224 => {
                                    black_box(
                                        execution::Sha224::hash(
                                            owner.execution().map_err(|e| format!("{e:?}"))?,
                                            black_box(bytes),
                                        )
                                        .map_err(|e| format!("{e:?}"))?,
                                    );
                                }
                                Algorithm::Sha256 => {
                                    black_box(
                                        execution::Sha256::hash(
                                            owner.execution().map_err(|e| format!("{e:?}"))?,
                                            black_box(bytes),
                                        )
                                        .map_err(|e| format!("{e:?}"))?,
                                    );
                                }
                            }
                        }
                        Ok(())
                    },
                    iterations,
                )?);
            }
            println!(
                "SHA256_BATCH_BENCH: algorithm={algorithm:?}; lanes=8; bytes={length}; samples=7; iterations={iterations}; portable_median_ns={portable}; selected_median_ns={selected}; dedicated_median_ns={dedicated:?}; report={report:?}; benefit_vs_portable={}",
                selected < portable
            );
        }
    }
    println!(
        "Timing is machine/workload-specific; no universal speedup or side-channel qualification."
    );
    Ok(())
}

fn measure(
    mut operation: impl FnMut() -> Result<(), String>,
    iterations: usize,
) -> Result<u128, String> {
    operation()?;
    let mut samples = [0_u128; 7];
    for sample in &mut samples {
        let start = Instant::now();
        for _ in 0..iterations {
            operation()?;
        }
        *sample = start.elapsed().as_nanos();
    }
    samples.sort();
    samples.get(3).copied().ok_or_else(|| "median".into())
}
