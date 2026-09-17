use crate::common::*;
use brynja_crypto_cpu_std::keccak_hardened_batch::Authority;
use brynja_hash_sha3::{Fips202BitString, hardened_batch::*};
use std::{hint::black_box, time::Instant};

fn bits(bytes: &[u8]) -> Result<Fips202BitString<'_>> {
    check(Fips202BitString::new(
        bytes,
        if bytes.is_empty() { 0 } else { 8 },
    ))
}

pub fn run(mode: &str) -> Result<()> {
    let owner = check(Authority::new(if mode == "prefer" {
        Mode::Prefer
    } else {
        Mode::Portable
    }))?;
    let selected = check(owner.executor(1))?;
    let portable = Executor::portable();
    for (name, algorithm) in [
        ("sha3-224", Algorithm::Sha3_224),
        ("sha3-256", Algorithm::Sha3_256),
        ("sha3-384", Algorithm::Sha3_384),
        ("sha3-512", Algorithm::Sha3_512),
        ("shake128", Algorithm::Shake128),
        ("shake256", Algorithm::Shake256),
        ("cshake128", Algorithm::Cshake128),
        ("cshake256", Algorithm::Cshake256),
    ] {
        for bytes in [0, algorithm.rate(), 4096, 16384] {
            for lanes in 1..=4 {
                for ragged in [false, true] {
                    let messages = messages::<4>(bytes, ragged);
                    let customized =
                        matches!(algorithm, Algorithm::Cshake128 | Algorithm::Cshake256);
                    let n = bits(if customized { b"benchmark" } else { b"" })?;
                    let s = bits(if customized { b"public workload" } else { b"" })?;
                    let output_bits = algorithm.fixed_output_bits().unwrap_or(4099);
                    let size = output_bits.div_ceil(8);
                    let mut inputs = core::array::from_fn(|_| None);
                    for (slot, message) in inputs.iter_mut().zip(&messages).take(lanes) {
                        *slot = Some(check(Input::with_customization(
                            algorithm,
                            bits(message)?,
                            n,
                            s,
                            output_bits,
                        ))?);
                    }
                    let mut expected = core::array::from_fn(|_| vec![0xa5; size + 1]);
                    let mut baseline_workspace = Workspace::new();
                    let mut selected_workspace = Workspace::new();
                    let mut staging = vec![0x5a; lanes * size + 7];
                    let mut cancel = || false;
                    check(portable.digest_public(
                        &inputs,
                        destinations(&mut expected, lanes, size),
                        &mut baseline_workspace,
                        &mut staging,
                        &mut Control::new(100_000, &mut cancel),
                        Sha3PublicDeclassification::acknowledge(),
                    ))?;
                    let mut output = core::array::from_fn(|_| vec![0xa5; size + 1]);
                    let mut kernel = String::from("None");
                    let (baseline_ns, selected_ns, calls) = measure(|use_selected| {
                        for (out, reference) in output.iter_mut().zip(&expected).take(lanes) {
                            for (byte, value) in out[..size].iter_mut().zip(reference) {
                                *byte = !value;
                            }
                        }
                        staging.fill(0x5a);
                        let executor = if use_selected { &selected } else { &portable };
                        let workspace = if use_selected {
                            &mut selected_workspace
                        } else {
                            &mut baseline_workspace
                        };
                        let mut control = Control::new(100_000, &mut cancel);
                        let start = Instant::now();
                        let (owned, report) = check(executor.digest_secret(
                            black_box(&inputs),
                            destinations(&mut output, lanes, size),
                            workspace,
                            &mut staging,
                            &mut control,
                        ))?;
                        for (index, reference) in expected.iter().enumerate() {
                            observe(
                                owned.expose(index),
                                (index < lanes).then_some(&reference[..size]),
                            )?;
                        }
                        drop(owned);
                        let elapsed = start.elapsed().as_nanos();
                        cleanup(&output, lanes, size)?;
                        if staging.iter().any(|byte| *byte != 0) {
                            return Err("benchmark staging cleanup".into());
                        }
                        if report
                            .vector_permutations
                            .checked_add(report.scalar_permutations)
                            != Some(control.used())
                        {
                            return Err("benchmark work accounting".into());
                        }
                        if use_selected {
                            kernel = report
                                .kernel
                                .map_or_else(|| "None".into(), |k| format!("{k:?}"));
                        }
                        Ok((elapsed, report.vector_calls))
                    })?;
                    let shape = if ragged { "ragged" } else { "balanced" };
                    println!(
                        "HARDENED_BATCH_BENCH: family=keccak; algorithm={name}; bytes={bytes}; lanes={lanes}; shape={shape}; mode={mode}; samples=7; portable_ns={baseline_ns}; selected_ns={selected_ns}; vector_calls={calls}; kernel={kernel}"
                    );
                }
            }
        }
    }
    Ok(())
}
