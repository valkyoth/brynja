//! End-to-end public-message measurements; no universal crossover claim.
use super::{Result, bits};
use brynja_hash_sha3::batch::{
    Algorithm, Control, Executor, Input, Kernel, Mode, PublicData, Workspace,
};
use std::{hint::black_box, time::Instant};

const SAMPLES: usize = 7;
const ALGORITHMS: [Algorithm; 8] = [
    Algorithm::Sha3_224,
    Algorithm::Sha3_256,
    Algorithm::Sha3_384,
    Algorithm::Sha3_512,
    Algorithm::Shake128,
    Algorithm::Shake256,
    Algorithm::Cshake128,
    Algorithm::Cshake256,
];

struct Buffers {
    storage: Vec<Vec<u8>>,
    staging: Vec<u8>,
    workspace: Workspace,
}
impl Buffers {
    fn new(inputs: &[Input<'_>]) -> Result<Self> {
        let total = inputs
            .iter()
            .try_fold(0_usize, |n, i| n.checked_add(i.output_bytes()))
            .ok_or("staging overflow")?;
        Ok(Self {
            storage: inputs.iter().map(|i| vec![0; i.output_bytes()]).collect(),
            staging: vec![0; total],
            workspace: Workspace::new(),
        })
    }
    fn measure(&mut self, executor: &Executor<'_>, inputs: &[Input<'_>]) -> Result<(u128, u64)> {
        let mut output: Vec<_> = self.storage.iter_mut().map(Vec::as_mut_slice).collect();
        let mut cancel = || false;
        let mut control = Control::new(100_000, &mut cancel);
        let start = Instant::now();
        let report = executor
            .digest(
                PublicData::new(black_box(inputs)),
                &mut output,
                &mut self.workspace,
                &mut self.staging,
                &mut control,
            )
            .map_err(|e| format!("benchmark digest: {e:?}"))?;
        let elapsed = start.elapsed().as_nanos();
        black_box(&output);
        Ok((elapsed, report.vector_calls))
    }
    fn poison(&mut self, expected: &[Vec<u8>]) {
        for (out, reference) in self.storage.iter_mut().zip(expected) {
            for (byte, value) in out.iter_mut().zip(reference) {
                *byte = !value;
            }
        }
    }
}

fn median(mut values: [u128; SAMPLES]) -> u128 {
    values.sort_unstable();
    values[SAMPLES / 2]
}

pub(super) fn run(executor: &Executor<'_>, mode: Mode, kernel: Option<Kernel>) -> Result<()> {
    let portable = Executor::portable();
    let mut cases = 0_usize;
    let mut total_vector = 0_u64;
    for algorithm in ALGORITHMS {
        for bytes in [0_usize, algorithm.rate(), 4096, 16384] {
            for lanes in 1_usize..=4 {
                if mode == Mode::Require && kernel.is_some_and(|k| lanes < k.width()) {
                    continue;
                }
                // Unequal lane lengths exercise tails; all retain at least one permutation.
                let messages: Vec<_> = (0..lanes)
                    .map(|lane| {
                        vec![
                            u8::try_from(lane).map_or(0, |n| n.wrapping_add(0x31));
                            bytes.saturating_sub(lane)
                        ]
                    })
                    .collect();
                let customized = matches!(algorithm, Algorithm::Cshake128 | Algorithm::Cshake256);
                let name: &[u8] = if customized { b"benchmark" } else { b"" };
                let custom: &[u8] = if customized { b"public workload" } else { b"" };
                let output_bits = algorithm.fixed_output_bits().unwrap_or(4099);
                let inputs: Vec<_> = messages
                    .iter()
                    .map(|message| {
                        Input::with_customization(
                            algorithm,
                            bits(
                                message,
                                message.len().checked_mul(8).ok_or("input overflow")?,
                            )?,
                            bits(name, name.len().checked_mul(8).ok_or("name overflow")?)?,
                            bits(
                                custom,
                                custom.len().checked_mul(8).ok_or("custom overflow")?,
                            )?,
                            output_bits,
                        )
                        .map_err(|e| format!("benchmark input: {e:?}").into())
                    })
                    .collect::<Result<_>>()?;
                let mut reference = Buffers::new(&inputs)?;
                let mut selected = Buffers::new(&inputs)?;
                reference.measure(&portable, &inputs)?;
                let expected = reference.storage.clone();
                let mut baseline_ns = [0; SAMPLES];
                let mut selected_ns = [0; SAMPLES];
                let mut vectors = 0_u64;
                for sample in 0..SAMPLES {
                    reference.poison(&expected);
                    selected.poison(&expected);
                    // Alternate order to reduce warm-cache/order bias. Allocations and
                    // result comparison are outside the measured digest operations.
                    let (baseline, candidate) = if sample.is_multiple_of(2) {
                        (
                            reference.measure(&portable, &inputs)?,
                            selected.measure(executor, &inputs)?,
                        )
                    } else {
                        let candidate = selected.measure(executor, &inputs)?;
                        (reference.measure(&portable, &inputs)?, candidate)
                    };
                    if reference.storage != expected
                        || selected.storage != expected
                        || baseline.1 != 0
                    {
                        return Err("benchmark output/portable-route mismatch".into());
                    }
                    baseline_ns[sample] = baseline.0;
                    selected_ns[sample] = candidate.0;
                    vectors = vectors.checked_add(candidate.1).ok_or("vector overflow")?;
                }
                if mode == Mode::Require && vectors == 0 {
                    return Err("required SIMD absent".into());
                }
                total_vector = total_vector
                    .checked_add(vectors)
                    .ok_or("total vector overflow")?;
                cases = cases.checked_add(1).ok_or("case overflow")?;
                println!(
                    "KECCAK_BATCH_BENCH: algorithm={algorithm:?}; bytes_max={bytes}; lanes={lanes}; output_bits={output_bits}; mode={mode:?}; kernel={kernel:?}; samples={SAMPLES}; portable_median_ns={}; selected_median_ns={}; vector_calls={vectors}",
                    median(baseline_ns),
                    median(selected_ns)
                );
            }
        }
    }
    println!(
        "KECCAK_BATCH_BENCHMARK: PASS; cases={cases}; vector_calls={total_vector}; threshold=caller-selected; public-only"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn median_is_order_independent() {
        assert_eq!(median([7, 2, 6, 1, 4, 3, 5]), 4);
    }
    #[test]
    fn poison_cannot_match_reference() -> Result<()> {
        let input = Input::new(Algorithm::Shake128, bits(&[], 0)?, 9)
            .map_err(|e| format!("input: {e:?}"))?;
        let mut buffer = Buffers::new(&[input])?;
        buffer.poison(&[vec![0, 0xff]]);
        assert_eq!(buffer.storage, [vec![0xff, 0]]);
        Ok(())
    }
}
