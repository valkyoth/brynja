//! Bounded synthetic contrasts, not constant-time qualification.
#![forbid(unsafe_code)]

use brynja_crypto::aes::{
    Aes192ExpandedKey, Aes192Key, Aes256ExpandedKey, Aes256Key, PublicCiphertext,
};
use std::{fmt::Write, hint::black_box, time::Instant};

const SAMPLES: usize = 512;
const REPEAT: usize = 4;
const WARMUP: usize = 32;
const MODES: [&str; 6] = [
    "encrypt-key",
    "encrypt-block",
    "decrypt-key",
    "decrypt-block",
    "public-key",
    "public-block",
];
type Result<T> = std::result::Result<T, String>;

// Construction, formatting and allocation outside the operation closure are
// outside the timer. The cached-operation route retains its schedule across all
// repetitions; cached-import measures construction/Drop, not encryption.
fn timed(measuring: bool, mut operation: impl FnMut() -> Result<()>) -> Result<u128> {
    let start = Instant::now();
    for _ in 0..if measuring { REPEAT } else { 1 } {
        operation()?;
    }
    Ok(start.elapsed().as_nanos())
}

macro_rules! width {
    ($trial:ident, $key:ident, $cached:ident, $k:literal, $s:literal) => {
        fn $trial(
            owner: &str,
            mode: &str,
            class: usize,
            measuring: bool,
        ) -> Result<(u128, String)> {
            if class > 1
                || !(MODES.contains(&mode) && matches!(owner, "ephemeral" | "cached")
                    || owner == "cached-import" && mode == "import-key")
            {
                return Err("unknown timing configuration".into());
            }
            let value = if class == 0 { 0 } else { 0xff };
            let input_key = [if mode.ends_with("-key") { value } else { 0x37 }; $k];
            let input = [if mode.ends_with("-block") {
                value
            } else {
                0x37
            }; 16];
            let mut storage = [0; $k];
            let mut schedule = [0; $s];
            let mut destination = [0; 16];
            let mut hex = String::new();
            let mut observe = |bytes: &[u8]| {
                black_box(bytes);
                if !measuring {
                    for byte in bytes {
                        write!(hex, "{byte:02x}").expect("String write");
                    }
                }
            };
            let elapsed = match owner {
                "ephemeral" => timed(measuring, || {
                    let key = $key::new(black_box(&input_key), black_box(&mut storage))
                        .map_err(|e| format!("{e:?}"))?;
                    if mode.starts_with("public-") {
                        key.encrypt_block_public(
                            black_box(&input),
                            &mut destination,
                            PublicCiphertext::acknowledge(),
                        )
                        .map_err(|e| format!("{e:?}"))?;
                        observe(&destination);
                    } else {
                        let block = if mode.starts_with("decrypt-") {
                            key.decrypt_block(black_box(&input), &mut destination)
                        } else {
                            key.encrypt_block(black_box(&input), &mut destination)
                        }
                        .map_err(|e| format!("{e:?}"))?;
                        observe(block.expose());
                    }
                    // Both ephemeral-key and secret-output Drop are timed.
                    Ok(())
                })?,
                "cached" => {
                    let key = $cached::new(black_box(&input_key), &mut schedule)
                        .map_err(|e| format!("{e:?}"))?;
                    timed(measuring, || {
                        let key = black_box(&key);
                        if mode.starts_with("public-") {
                            key.encrypt_block_public(
                                black_box(&input),
                                &mut destination,
                                PublicCiphertext::acknowledge(),
                            )
                            .map_err(|e| format!("{e:?}"))?;
                            observe(&destination);
                        } else {
                            let block = if mode.starts_with("decrypt-") {
                                key.decrypt_block(black_box(&input), &mut destination)
                            } else {
                                key.encrypt_block(black_box(&input), &mut destination)
                            }
                            .map_err(|e| format!("{e:?}"))?;
                            observe(block.expose());
                        }
                        Ok(())
                    })?
                    // Cached schedule Drop occurs after the timer stops.
                }
                "cached-import" => timed(measuring, || {
                    let key = $cached::new(black_box(&input_key), black_box(&mut schedule))
                        .map_err(|e| format!("{e:?}"))?;
                    black_box(&key);
                    if !measuring {
                        // Independently validate the imported schedule before
                        // measuring import/Drop alone; no schedule export API.
                        let block = key
                            .encrypt_block(&input, &mut destination)
                            .map_err(|e| format!("{e:?}"))?;
                        observe(block.expose());
                    }
                    Ok(())
                })?,
                _ => return Err("unknown timing owner".into()),
            };
            Ok((elapsed, hex))
        }
    };
}

width!(aes192, Aes192Key, Aes192ExpandedKey, 24, 208);
width!(aes256, Aes256Key, Aes256ExpandedKey, 32, 240);

type Trial = fn(&str, &str, usize, bool) -> Result<(u128, String)>;

fn run(phase: &str) -> Result<()> {
    if !matches!(phase, "preflight" | "measure") {
        return Err("expected preflight or measure".into());
    }
    let measuring = phase == "measure";
    println!("AES_WIDE_TIMING_POLICY {SAMPLES} {REPEAT} {WARMUP}");
    let mut records = Vec::new();
    for (bits, trial) in [(192, aes192 as Trial), (256, aes256 as Trial)] {
        for owner in ["ephemeral", "cached", "cached-import"] {
            let modes: &[&str] = if owner == "cached-import" {
                &["import-key"]
            } else {
                &MODES
            };
            for mode in modes {
                if !measuring {
                    for class in 0..2 {
                        let (_, hex) = trial(owner, mode, class, false)?;
                        records.push(format!("VECTOR {bits} {owner} {mode} {class} {hex}"));
                    }
                    continue;
                }
                // Fixed 256 AB / 256 BA pairs, preceded by 32 warmup pairs.
                // No sample rejection, adaptive stopping or retry-to-pass.
                for sample in 0..SAMPLES + WARMUP {
                    let first = sample % 2;
                    let mut elapsed = [0; 2];
                    for class in [first, 1 - first] {
                        elapsed[class] = trial(owner, mode, class, true)?.0;
                    }
                    if sample >= WARMUP {
                        records.push(format!(
                            "SAMPLE {bits} {owner} {mode} {} {} {}",
                            sample - WARMUP,
                            elapsed[0],
                            elapsed[1]
                        ));
                    }
                }
            }
        }
    }
    for record in records {
        println!("{record}");
    }
    println!("AES_WIDE_TIMING_END {phase}");
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 1 {
        return Err("expected one phase".into());
    }
    run(&args[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_preflight_routes_produce_one_block() {
        for trial in [aes192 as Trial, aes256 as Trial] {
            for class in 0..2 {
                for owner in ["ephemeral", "cached"] {
                    for mode in MODES {
                        assert_eq!(trial(owner, mode, class, false).unwrap().1.len(), 32);
                    }
                }
                assert_eq!(
                    trial("cached-import", "import-key", class, false)
                        .unwrap()
                        .1
                        .len(),
                    32
                );
            }
        }
    }

    #[test]
    fn malformed_configurations_fail_before_measurement() {
        assert!(run("unknown").is_err());
        for trial in [aes192 as Trial, aes256 as Trial] {
            for (owner, mode, class) in [
                ("unknown", "encrypt-key", 0),
                ("cached", "unknown", 0),
                ("cached-import", "encrypt-key", 0),
                ("ephemeral", "import-key", 0),
                ("cached", "encrypt-key", 2),
            ] {
                assert!(trial(owner, mode, class, true).is_err());
            }
        }
    }
}
