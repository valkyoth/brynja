//! Public synthetic workloads; no secret inputs or side-channel qualification.
use brynja_crypto_cpu_std::keccak_hardened_batch::{Authority, Mode};
use brynja_hash_parallel::{
    Fips202BitString, ParallelHashSecretOutput,
    execution::{Collector, Identity, Mode as RootMode, Plan, batch},
};
use brynja_hash_parallel_std::{
    CancellationToken,
    execution::batch::{Config, Executor, Preference, Report, Request},
};
use std::{hint::black_box, time::Instant};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const SAMPLES: usize = 7;

fn check<T, E: core::fmt::Debug>(result: std::result::Result<T, E>) -> Result<T> {
    result.map_err(|e| format!("{e:?}").into())
}

fn scheduled<'a>(
    request: &Request<'_>,
    bytes: &'a mut [u8],
    valid: u8,
) -> Result<ParallelHashSecretOutput<'a>> {
    let plan = check(Plan::new_bits(
        request.identity,
        request.input,
        request.block_size,
        4096,
    ))?;
    let mut root = check(Collector::new_bits(
        &plan,
        RootMode::Portable,
        request.customization,
    ))?;
    let mut workspace = batch::Workspace::new();
    let mut cancel = || false;
    let report = check(root.execute_batched(
        &batch::Executor::portable(),
        &mut workspace,
        &mut batch::Control::new(100_000, &mut cancel),
    ))?;
    if report.vector_calls != 0 || report.scalar_leaves != plan.leaf_count() {
        return Err("scheduled portable accounting".into());
    }
    if matches!(
        request.identity,
        Identity::ParallelHashXof128 | Identity::ParallelHashXof256
    ) {
        check(check(root.finalize_xof())?.squeeze_final_secret(bytes, valid))
    } else {
        check(root.finalize_secret_bits(bytes, valid))
    }
}

fn cleanup(bytes: &[u8], size: usize) -> Result<()> {
    if bytes[..size].iter().any(|byte| *byte != 0) || bytes.last() != Some(&0xa5) {
        return Err("benchmark secret Drop/canary cleanup".into());
    }
    Ok(())
}

fn report_check(report: Report, leaves: usize, workers: usize, width: Option<usize>) -> Result<()> {
    let groups = leaves.div_ceil(4);
    let accelerated = width.map_or(0, |width| leaves / width * width);
    if report.execution.leaves != leaves as u128
        || report.groups != groups as u128
        || report.execution.thread_width != workers.min(groups)
        || report.execution.root.is_some()
        || report.execution.accelerated_leaves != accelerated as u128
        || (report.vector_calls > 0) != (accelerated > 0)
    {
        return Err("benchmark leaf/group/thread/route accounting".into());
    }
    Ok(())
}

struct Workload<'a> {
    request: Request<'a>,
    expected: Vec<u8>,
    output: Vec<u8>,
    valid: u8,
    workers: usize,
    width: Option<usize>,
    executor: Executor,
}
impl Workload<'_> {
    fn sample(&mut self, threaded: bool) -> Result<(u128, Option<Report>)> {
        let size = self.expected.len();
        for (out, value) in self.output[..size].iter_mut().zip(&self.expected) {
            *out = !value;
        }
        let cancellation = CancellationToken::new();
        let start = Instant::now();
        let (owned, report) = if threaded {
            let (owned, report) = check(self.executor.hash_secret_bits(
                black_box(&self.request),
                &mut self.output[..size],
                self.valid,
                &cancellation,
            ))?;
            (owned, Some(report))
        } else {
            (
                scheduled(
                    black_box(&self.request),
                    &mut self.output[..size],
                    self.valid,
                )?,
                None,
            )
        };
        if black_box(owned.expose()) != self.expected {
            return Err("benchmark output mismatch".into());
        }
        drop(owned);
        let elapsed = start.elapsed().as_nanos();
        cleanup(&self.output, size)?;
        if let Some(report) = report {
            report_check(
                report,
                self.request
                    .input
                    .as_bytes()
                    .len()
                    .div_ceil(self.request.block_size),
                self.workers,
                self.width,
            )?;
        }
        if elapsed == 0 {
            return Err("empty benchmark timing".into());
        }
        Ok((elapsed, report))
    }
}

fn measure(
    mut sample: impl FnMut(bool) -> Result<(u128, Option<Report>)>,
) -> Result<(u128, u128, Report, u64)> {
    let (_, expected) = sample(true)?;
    let expected = expected.ok_or("missing threaded report")?;
    if sample(false)?.1.is_some() {
        return Err("baseline report".into());
    }
    let mut baseline = [0; SAMPLES];
    let mut threaded = [0; SAMPLES];
    let mut calls = 0_u64;
    for index in 0..SAMPLES {
        let (a, b) = if index % 2 == 0 {
            (sample(false)?, sample(true)?)
        } else {
            let b = sample(true)?;
            (sample(false)?, b)
        };
        if a.1.is_some() || b.1 != Some(expected) || a.0 == 0 || b.0 == 0 {
            return Err("unstable benchmark work or empty timing".into());
        }
        calls = calls
            .checked_add(expected.vector_calls)
            .ok_or("benchmark vector counter overflow")?;
        baseline[index] = a.0;
        threaded[index] = b.0;
    }
    baseline.sort_unstable();
    threaded.sort_unstable();
    Ok((
        baseline[SAMPLES / 2],
        threaded[SAMPLES / 2],
        expected,
        calls,
    ))
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 1 || !["portable", "prefer"].contains(&args[0].as_str()) {
        return Err("expected portable|prefer".into());
    }
    let mode = args[0].as_str();
    let preference = if mode == "prefer" {
        Preference::Prefer
    } else {
        Preference::Portable
    };
    let owner = check(Authority::new(if mode == "prefer" {
        Mode::Prefer
    } else {
        Mode::Portable
    }))?;
    let kernel = check(owner.kernel())?;
    let width = kernel.map(|kernel| kernel.width());
    let kernel_name = kernel.map_or_else(|| "None".into(), |kernel| format!("{kernel:?}"));
    let mut cases = 0_usize;
    for (name, identity, output_bits) in [
        ("parallel128", Identity::ParallelHash128, 256_usize),
        ("parallel256", Identity::ParallelHash256, 256),
        ("parallelxof128", Identity::ParallelHashXof128, 4099),
        ("parallelxof256", Identity::ParallelHashXof256, 4099),
    ] {
        for length in [0_usize, 65, 4096, 16387] {
            let message: Vec<_> = (0..length).map(|index| index.to_le_bytes()[0]).collect();
            for block_size in [64, 1024] {
                for workers in [1, 2, 4] {
                    let request = Request {
                        identity,
                        input: check(Fips202BitString::new(
                            &message,
                            if length == 0 { 0 } else { 8 },
                        ))?,
                        block_size,
                        customization: check(Fips202BitString::new(b"public benchmark", 8))?,
                    };
                    let size = output_bits.div_ceil(8);
                    let valid = if output_bits % 8 == 0 { 8 } else { 3 };
                    let mut output = vec![0xa5; size + 1];
                    let owned = scheduled(&request, &mut output[..size], valid)?;
                    // Copying this generated public vector is intentional, not secret storage.
                    let expected = owned.expose().to_vec();
                    drop(owned);
                    cleanup(&output, size)?;
                    let executor = check(Executor::new(Config {
                        workers,
                        max_leaves: 4096,
                        root: Preference::Portable,
                        leaves: preference,
                        minimum_permutations: 1,
                        max_group_permutations: 4096,
                    }))?;
                    let mut workload = Workload {
                        request,
                        expected,
                        output,
                        valid,
                        workers,
                        width,
                        executor,
                    };
                    let (baseline_ns, threaded_ns, report, calls) =
                        measure(|threaded| workload.sample(threaded))?;
                    println!(
                        "PARALLELHASH_BATCH_BENCH: algorithm={name}; bytes={length}; block={block_size}; workers={workers}; output_bits={output_bits}; mode={mode}; selected_kernel={kernel_name}; samples=7; scheduled_ns={baseline_ns}; threaded_ns={threaded_ns}; groups={}; thread_width={}; accelerated_leaves={}; vector_calls={calls}",
                        report.groups,
                        report.execution.thread_width,
                        report.execution.accelerated_leaves
                    );
                    cases = cases.checked_add(1).ok_or("case count overflow")?;
                }
            }
        }
    }
    if cases != 96 {
        return Err("benchmark workload coverage".into());
    }
    println!(
        "PARALLELHASH_BATCH_BENCHMARK: PASS; cases=96; samples=7; root=portable; threshold=1; timing=hash,threads,validate,drop; independent_review=NO"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn report() -> Report {
        Report {
            execution: brynja_hash_parallel_std::execution::Report {
                root: None,
                leaves: 4,
                accelerated_leaves: 4,
                thread_width: 1,
            },
            groups: 1,
            vector_calls: 1,
            vector_permutations: 4,
            scalar_permutations: 0,
        }
    }
    #[test]
    fn medians_routes_and_counts_are_checked() {
        let good = report();
        let mut index = 0;
        let measured = measure(|threaded| {
            index += 1;
            Ok((index, threaded.then_some(good)))
        });
        assert_eq!(measured.ok(), Some((10, 9, good, 7)));
        assert!(measure(|_| Ok((1, None))).is_err());
        assert!(measure(|_| Ok((1, Some(good)))).is_err());
        assert!(measure(|threaded| Ok((0, threaded.then_some(good)))).is_err());
        let mut overflow = good;
        overflow.vector_calls = u64::MAX;
        assert!(measure(|threaded| Ok((1, threaded.then_some(overflow)))).is_err());
        let mut count = 0;
        assert!(
            measure(|threaded| {
                count += 1;
                let mut changed = good;
                changed.vector_calls = count;
                Ok((1, threaded.then_some(changed)))
            })
            .is_err()
        );
        assert!(report_check(good, 4, 1, Some(4)).is_ok());
        assert!(report_check(good, 5, 1, Some(4)).is_err());
        assert!(report_check(good, 4, 1, None).is_err());
        assert!(cleanup(&[0, 0xa5], 1).is_ok());
        assert!(cleanup(&[1, 0xa5], 1).is_err());
        assert!(cleanup(&[0, 0], 1).is_err());
    }
}
