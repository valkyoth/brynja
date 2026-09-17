use crate::common::*;
use brynja_hash_sha2::{BitString, Sha512TBits};
use std::{hint::black_box, time::Instant};

macro_rules! family {
    ($fn:ident, $host:ident, $api:ident, $capacity:literal, $block:literal, $family:literal, $algorithms:expr) => {
        pub fn $fn(mode: &str) -> Result<()> {
            use brynja_crypto_cpu_std::$host::{Authority, Mode};
            use brynja_hash_sha2::$api::{Algorithm, Control, Executor, Input, PublicDeclassification, Workspace};
            let owner = check(Authority::new(if mode == "prefer" { Mode::Prefer } else { Mode::Portable }))?;
            let selected = check(owner.executor(1))?;
            let portable = Executor::portable();
            for (name, algorithm) in $algorithms {
                for bytes in [0, $block, 4096, 16384] {
                    for lanes in 1..=$capacity {
                        for ragged in [false, true] {
                            let messages = messages::<$capacity>(bytes, ragged);
                            let mut inputs = core::array::from_fn(|_| None);
                            for (slot, message) in inputs.iter_mut().zip(&messages).take(lanes) {
                                *slot = Some(Input::new(algorithm, check(BitString::new(message, if message.is_empty() { 0 } else { 8 }))?));
                            }
                            let size = algorithm.output_bytes();
                            let mut expected = core::array::from_fn(|_| vec![0xa5; size + 1]);
                            let mut baseline_workspace = Workspace::new();
                            let mut selected_workspace = Workspace::new();
                            let mut cancel = || false;
                            check(portable.digest_public(&inputs, destinations(&mut expected, lanes, size),
                                &mut baseline_workspace, &mut Control::new(100_000, &mut cancel), PublicDeclassification::acknowledge()))?;
                            let mut output = core::array::from_fn(|_| vec![0xa5; size + 1]);
                            let mut kernel = String::from("None");
                            let (baseline_ns, selected_ns, calls) = measure(|use_selected| {
                                // Poison against the exact public reference, not a possibly correct constant.
                                for (out, reference) in output.iter_mut().zip(&expected).take(lanes) {
                                    for (byte, value) in out[..size].iter_mut().zip(reference) { *byte = !value; }
                                }
                                let executor = if use_selected { &selected } else { &portable };
                                let workspace = if use_selected { &mut selected_workspace } else { &mut baseline_workspace };
                                let mut control = Control::new(100_000, &mut cancel);
                                let start = Instant::now();
                                let (owned, report) = check(executor.digest_secret(black_box(&inputs), destinations(&mut output, lanes, size), workspace, &mut control))?;
                                for (index, reference) in expected.iter().enumerate() {
                                    observe(owned.expose(index), (index < lanes).then_some(&reference[..size]))?;
                                }
                                drop(owned);
                                let elapsed = start.elapsed().as_nanos();
                                cleanup(&output, lanes, size)?;
                                if report.vector_blocks.checked_add(report.scalar_blocks) != Some(control.used()) {
                                    return Err("benchmark work accounting".into());
                                }
                                if use_selected { kernel = report.kernel.map_or_else(|| "None".into(), |k| format!("{k:?}")); }
                                Ok((elapsed, report.vector_calls))
                            })?;
                            let shape = if ragged { "ragged" } else { "balanced" };
                            println!("HARDENED_BATCH_BENCH: family={}; algorithm={name}; bytes={bytes}; lanes={lanes}; shape={shape}; mode={mode}; samples=7; portable_ns={baseline_ns}; selected_ns={selected_ns}; vector_calls={calls}; kernel={kernel}", $family);
                        }
                    }
                }
            }
            Ok(())
        }
    };
}

family!(
    narrow,
    sha256_hardened_batch,
    hardened_batch,
    8,
    64,
    "sha256",
    [("sha224", Algorithm::Sha224), ("sha256", Algorithm::Sha256)]
);
family!(
    wide,
    sha512_hardened_batch,
    hardened_batch512,
    4,
    128,
    "sha512",
    [
        ("sha384", Algorithm::Sha384),
        ("sha512", Algorithm::Sha512),
        ("sha512-224", Algorithm::Sha512_224),
        ("sha512-256", Algorithm::Sha512_256),
        (
            "sha512-t17",
            Algorithm::Sha512T(check(Sha512TBits::new(17))?)
        ),
        (
            "sha512-t224",
            Algorithm::Sha512T(check(Sha512TBits::new(224))?)
        ),
        (
            "sha512-t256",
            Algorithm::Sha512T(check(Sha512TBits::new(256))?)
        ),
        (
            "sha512-t511",
            Algorithm::Sha512T(check(Sha512TBits::new(511))?)
        )
    ]
);
