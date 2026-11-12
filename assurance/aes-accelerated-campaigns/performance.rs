//! Public-fixture performance diagnostic, not side-channel acceptance.
#![forbid(unsafe_code)]

#[cfg(feature = "facade")]
use brynja::crypto::aes as portable;
use brynja_aes_accelerated_fixture::{aes, forced_authority};
#[cfg(feature = "direct")]
use brynja_crypto::aes as portable;
use std::{hint::black_box, time::Instant};

const SAMPLES: usize = 9;
const BATCH: usize = 64;
const WARMUP: usize = 8;
const OPERATIONS: [&str; 4] = ["construct-clear", "encrypt", "decrypt", "public"];
const PLAIN: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];
type Result<T> = std::result::Result<T, String>;

fn batch(
    repetitions: usize,
    measure: bool,
    expected: [u8; 16],
    mut operation: impl FnMut() -> Result<[u8; 16]>,
) -> Result<u128> {
    // Routing, result observation and clearing are intentionally included.
    // Printing and the final known-answer comparison are outside the timer.
    let start = measure.then(Instant::now);
    let mut last = [0; 16];
    for _ in 0..repetitions {
        last = black_box(operation()?);
    }
    let elapsed = start.map_or(0, |start| start.elapsed().as_nanos());
    if last != expected {
        return Err("known answer or clearing mismatch".into());
    }
    Ok(elapsed)
}

macro_rules! owner_trial {
    ($make:expr, $storage:ident, $operation:ident, $cipher:ident, $repeat:ident, $measure:ident) => {{
        if $operation == "construct-clear" {
            batch($repeat, $measure, [0; 16], || {
                let key = $make.map_err(|error| format!("{error:?}"))?;
                black_box(&key);
                key.clear();
                // Fold the whole caller-owned storage, not just its first block.
                let residue = black_box(&$storage).iter().fold(0u8, |a, b| a | b);
                Ok([residue; 16])
            })
        } else {
            // Setup and teardown of the persistent owner are outside this timer.
            let key = $make.map_err(|error| format!("{error:?}"))?;
            let mut output = [0; 16];
            let input = if $operation == "decrypt" {
                $cipher
            } else {
                PLAIN
            };
            let expected = if $operation == "decrypt" {
                PLAIN
            } else {
                $cipher
            };
            let elapsed = batch($repeat, $measure, expected, || {
                if $operation == "public" {
                    black_box(&key)
                        .encrypt_block_public(
                            black_box(&input),
                            &mut output,
                            portable::PublicCiphertext::acknowledge(),
                        )
                        .map_err(|error| format!("{error:?}"))?;
                    Ok(*black_box(&output))
                } else {
                    let block = if $operation == "decrypt" {
                        black_box(&key).decrypt_block(black_box(&input), &mut output)
                    } else {
                        black_box(&key).encrypt_block(black_box(&input), &mut output)
                    }
                    .map_err(|error| format!("{error:?}"))?;
                    let observed: [u8; 16] = black_box(block.expose())
                        .try_into()
                        .map_err(|_| "block width")?;
                    block.clear();
                    Ok(observed)
                }
            })?;
            key.clear();
            if $storage.iter().any(|byte| *byte != 0)
                || ($operation != "public" && output.iter().any(|byte| *byte != 0))
            {
                return Err("owner/output clearing mismatch".into());
            }
            Ok(elapsed)
        }
    }};
}

macro_rules! width {
    ($name:ident, $raw:ident, $cached:ident, $k:literal, $s:literal, $cipher:expr) => {
        fn $name(
            authority: &aes::Authority,
            backend: &str,
            owner: &str,
            operation: &str,
            repeat: usize,
            measure: bool,
        ) -> Result<u128> {
            if !OPERATIONS.contains(&operation) || repeat == 0 || repeat > BATCH {
                return Err("invalid operation or batch size".into());
            }
            let input_key: [u8; $k] = std::array::from_fn(|i| i as u8);
            let cipher: [u8; 16] = $cipher;
            let mut raw = [0u8; $k];
            let mut schedule = [0u8; $s];
            match (backend, owner) {
                ("portable", "raw") => owner_trial!(
                    portable::$raw::new(black_box(&input_key), black_box(&mut raw)),
                    raw,
                    operation,
                    cipher,
                    repeat,
                    measure
                ),
                ("portable", "cached") => owner_trial!(
                    portable::$cached::new(black_box(&input_key), black_box(&mut schedule)),
                    schedule,
                    operation,
                    cipher,
                    repeat,
                    measure
                ),
                ("accelerated", "raw") => owner_trial!(
                    aes::$raw::new(authority, black_box(&input_key), black_box(&mut raw)),
                    raw,
                    operation,
                    cipher,
                    repeat,
                    measure
                ),
                ("accelerated", "cached") => owner_trial!(
                    aes::$cached::new(authority, black_box(&input_key), black_box(&mut schedule)),
                    schedule,
                    operation,
                    cipher,
                    repeat,
                    measure
                ),
                _ => Err("invalid backend or owner".into()),
            }
        }
    };
}

// FIPS 197 examples: sequential keys and 001122...eeff plaintext.
width!(
    aes128,
    Aes128Key,
    Aes128ExpandedKey,
    16,
    176,
    [
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5,
        0x5a
    ]
);
width!(
    aes192,
    Aes192Key,
    Aes192ExpandedKey,
    24,
    208,
    [
        0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71,
        0x91
    ]
);
width!(
    aes256,
    Aes256Key,
    Aes256ExpandedKey,
    32,
    240,
    [
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60,
        0x89
    ]
);

type Trial = fn(&aes::Authority, &str, &str, &str, usize, bool) -> Result<u128>;
const WIDTHS: [(usize, Trial); 3] = [(128, aes128), (192, aes192), (256, aes256)];

fn preflight(authority: &aes::Authority) -> Result<()> {
    for (_, trial) in WIDTHS {
        for owner in ["raw", "cached"] {
            for operation in OPERATIONS {
                for backend in ["portable", "accelerated"] {
                    if trial(authority, backend, owner, operation, 1, false)? != 0 {
                        return Err("preflight unexpectedly measured time".into());
                    }
                }
            }
        }
    }
    Ok(())
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 1 || !matches!(args[0].as_str(), "--check" | "--measure") {
        return Err("expected --check or --measure".into());
    }
    let authority = forced_authority().map_err(|error| error.to_string())?;
    let authority = authority.get().map_err(|error| error.to_string())?;
    preflight(authority)?;
    println!("AES_PERFORMANCE_PREFLIGHT_PASS: 48 cases");
    if args[0] == "--check" {
        return Ok(());
    }
    println!("AES_PERFORMANCE_POLICY: {SAMPLES} {BATCH} {WARMUP}");
    for (bits, trial) in WIDTHS {
        for owner in ["raw", "cached"] {
            for operation in OPERATIONS {
                for _ in 0..WARMUP {
                    for backend in ["portable", "accelerated"] {
                        trial(authority, backend, owner, operation, BATCH, false)?;
                    }
                }
                for sample in 0..SAMPLES {
                    // Alternate paired order; never choose samples by outcome.
                    let order = if sample % 2 == 0 {
                        ["portable", "accelerated"]
                    } else {
                        ["accelerated", "portable"]
                    };
                    let mut durations = [0u128; 2];
                    for (index, backend) in order.iter().enumerate() {
                        durations[index] =
                            trial(authority, backend, owner, operation, BATCH, true)?;
                    }
                    for (index, backend) in order.iter().enumerate() {
                        println!(
                            "SAMPLE {bits} {owner} {operation} {sample} {backend} {}",
                            durations[index]
                        );
                    }
                }
            }
        }
    }
    println!("AES_PERFORMANCE_END: 432 samples; diagnostic only");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("AES performance failed: {error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_route_matches_vectors_and_clears() -> Result<()> {
        let authority = forced_authority().map_err(|e| e.to_string())?;
        preflight(authority.get().map_err(|e| e.to_string())?)
    }

    #[test]
    fn malformed_configuration_is_rejected() -> Result<()> {
        let authority = forced_authority().map_err(|e| e.to_string())?;
        let a = authority.get().map_err(|e| e.to_string())?;
        for (_, trial) in WIDTHS {
            for (backend, owner, operation, count) in [
                ("other", "raw", "encrypt", 1),
                ("portable", "other", "encrypt", 1),
                ("portable", "raw", "other", 1),
                ("portable", "raw", "encrypt", 0),
                ("portable", "raw", "encrypt", BATCH + 1),
            ] {
                assert!(trial(a, backend, owner, operation, count, false).is_err());
            }
        }
        Ok(())
    }

    #[test]
    fn wrong_output_or_operation_failure_cannot_complete_batch() {
        assert!(batch(1, false, [1; 16], || Ok([0; 16])).is_err());
        assert!(batch(1, false, [0; 16], || Err("injected".into())).is_err());
    }

    #[test]
    fn policy_and_operation_population_are_fixed() {
        assert_eq!((SAMPLES, BATCH, WARMUP), (9, 64, 8));
        assert_eq!(WIDTHS.len() * 2 * OPERATIONS.len() * 2, 48);
        assert_eq!(48 * SAMPLES, 432);
    }
}
