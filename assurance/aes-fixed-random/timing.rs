//! Fixed-versus-pseudorandom public fixtures; bounded host observation only.
#![forbid(unsafe_code)]

use brynja_aes_public_api_fixture::aes::{
    Aes128ExpandedKey, Aes128Key, Aes192ExpandedKey, Aes192Key, Aes256ExpandedKey, Aes256Key,
    PublicCiphertext,
};
use std::{fmt::Write, hint::black_box, time::Instant};

const SAMPLES: usize = 8192;
const REPEAT: usize = 4;
const WARMUP: usize = 256;
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
            input_key: &[u8; 32],
            input: &[u8; 16],
            measuring: bool,
        ) -> Result<(u128, String)> {
            if !(MODES.contains(&mode) && matches!(owner, "ephemeral" | "cached")
                || owner == "cached-import" && mode == "import-key")
            {
                return Err("unknown timing configuration".into());
            }
            let input_key: &[u8; $k] = input_key[..$k].try_into().map_err(|_| "key width")?;
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
                    let key = $key::new(black_box(input_key), black_box(&mut storage))
                        .map_err(|e| format!("{e:?}"))?;
                    if mode.starts_with("public-") {
                        key.encrypt_block_public(
                            black_box(input),
                            &mut destination,
                            PublicCiphertext::acknowledge(),
                        )
                        .map_err(|e| format!("{e:?}"))?;
                        observe(&destination);
                    } else {
                        let block = if mode.starts_with("decrypt-") {
                            key.decrypt_block(black_box(input), &mut destination)
                        } else {
                            key.encrypt_block(black_box(input), &mut destination)
                        }
                        .map_err(|e| format!("{e:?}"))?;
                        observe(block.expose());
                    }
                    // Both ephemeral-key and secret-output Drop are timed.
                    Ok(())
                })?,
                "cached" => {
                    let key = $cached::new(black_box(input_key), &mut schedule)
                        .map_err(|e| format!("{e:?}"))?;
                    timed(measuring, || {
                        let key = black_box(&key);
                        if mode.starts_with("public-") {
                            key.encrypt_block_public(
                                black_box(input),
                                &mut destination,
                                PublicCiphertext::acknowledge(),
                            )
                            .map_err(|e| format!("{e:?}"))?;
                            observe(&destination);
                        } else {
                            let block = if mode.starts_with("decrypt-") {
                                key.decrypt_block(black_box(input), &mut destination)
                            } else {
                                key.encrypt_block(black_box(input), &mut destination)
                            }
                            .map_err(|e| format!("{e:?}"))?;
                            observe(block.expose());
                        }
                        Ok(())
                    })?
                    // Cached schedule Drop occurs after the timer stops.
                }
                "cached-import" => timed(measuring, || {
                    let key = $cached::new(black_box(input_key), black_box(&mut schedule))
                        .map_err(|e| format!("{e:?}"))?;
                    black_box(&key);
                    if !measuring {
                        // Independently validate the imported schedule before
                        // measuring import/Drop alone; no schedule export API.
                        let block = key
                            .encrypt_block(input, &mut destination)
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

width!(aes128, Aes128Key, Aes128ExpandedKey, 16, 176);
width!(aes192, Aes192Key, Aes192ExpandedKey, 24, 208);
width!(aes256, Aes256Key, Aes256ExpandedKey, 32, 240);

type Trial = fn(&str, &str, &[u8; 32], &[u8; 16], bool) -> Result<(u128, String)>;

const SEED: u64 = 0x0272_f17e_d00d_0001;

// SplitMix64 is only a reproducible public test-input generator, never a
// cryptographic RNG. Generate the full corpus and order before timing.
fn next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Case {
    key: [u8; 32],
    block: [u8; 16],
    first: usize,
}

fn corpus(campaign: u64) -> Vec<Case> {
    let mut state = SEED ^ campaign;
    (0..WARMUP + SAMPLES)
        .map(|_| {
            let mut key = [0; 32];
            let mut block = [0; 16];
            for chunk in key.as_chunks_mut::<8>().0 {
                *chunk = next(&mut state).to_le_bytes();
            }
            for chunk in block.as_chunks_mut::<8>().0 {
                *chunk = next(&mut state).to_le_bytes();
            }
            Case {
                key,
                block,
                first: usize::from(next(&mut state) & 1 != 0),
            }
        })
        .collect()
}

fn inputs(case: &Case, mode: &str, class: usize) -> ([u8; 32], [u8; 16]) {
    let key = if mode.ends_with("-key") {
        if class == 0 { [0; 32] } else { case.key }
    } else {
        [0x37; 32]
    };
    let block = if mode.ends_with("-block") {
        if class == 0 { [0; 16] } else { case.block }
    } else {
        [0x37; 16]
    };
    (key, block)
}

fn run(phase: &str) -> Result<()> {
    if !matches!(phase, "preflight" | "measure") {
        return Err("expected preflight or measure".into());
    }
    println!("AES_FIXED_RANDOM_POLICY {SAMPLES} {REPEAT} {WARMUP} {SEED}");
    let mut campaign = 0;
    for (bits, trial) in [
        (128, aes128 as Trial),
        (192, aes192 as Trial),
        (256, aes256 as Trial),
    ] {
        for owner in ["ephemeral", "cached", "cached-import"] {
            let modes: &[&str] = if owner == "cached-import" {
                &["import-key"]
            } else {
                &MODES
            };
            for mode in modes {
                let cases = corpus(campaign);
                campaign += 1;
                if phase == "preflight" {
                    for sample in [0, SAMPLES / 2, SAMPLES - 1] {
                        let case = &cases[WARMUP + sample];
                        for class in 0..2 {
                            let (key, block) = inputs(case, mode, class);
                            let (_, hex) = trial(owner, mode, &key, &block, false)?;
                            println!("VECTOR {bits} {owner} {mode} {sample} {class} {hex}");
                        }
                    }
                    continue;
                }
                // Buffer integer records; no allocation, formatting or output
                // between measurements. All setup below is outside the timer.
                let mut records = Vec::with_capacity(SAMPLES);
                for (index, case) in cases.iter().enumerate() {
                    let pair = [inputs(case, mode, 0), inputs(case, mode, 1)];
                    let mut elapsed = [0; 2];
                    for class in [case.first, 1 - case.first] {
                        elapsed[class] =
                            trial(owner, mode, &pair[class].0, &pair[class].1, true)?.0;
                    }
                    if index >= WARMUP {
                        records.push((case.first, elapsed));
                    }
                }
                for (sample, (first, elapsed)) in records.iter().enumerate() {
                    println!(
                        "SAMPLE {bits} {owner} {mode} {sample} {first} {} {}",
                        elapsed[0], elapsed[1]
                    );
                }
            }
        }
    }
    println!("AES_FIXED_RANDOM_END {phase}");
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
    fn public_generator_and_population_are_stable() {
        let mut state = 0;
        assert_eq!(next(&mut state), 0xe220_a839_7b1d_cdaf);
        assert_eq!(next(&mut state), 0x6e78_9e6a_a1b9_65f4);
        let cases = corpus(0);
        assert_eq!(cases.len(), SAMPLES + WARMUP);
        assert_eq!(cases, corpus(0));
        assert_ne!(cases, corpus(1));
        assert!(cases.iter().any(|c| c.first == 0));
        assert!(cases.iter().any(|c| c.first == 1));
        assert_ne!(cases[WARMUP].key, cases[WARMUP + 1].key);
        assert_ne!(cases[WARMUP].block, cases[WARMUP + 1].block);
    }

    #[test]
    fn classes_vary_only_the_declared_field() {
        let case = &corpus(0)[WARMUP];
        for mode in MODES.into_iter().chain(["import-key"]) {
            let fixed = inputs(case, mode, 0);
            let random = inputs(case, mode, 1);
            if mode.ends_with("-key") {
                assert_eq!(fixed.0, [0; 32]);
                assert_eq!(random.0, case.key);
                assert_eq!(fixed.1, [0x37; 16]);
                assert_eq!(fixed.1, random.1);
            } else {
                assert_eq!(fixed.1, [0; 16]);
                assert_eq!(random.1, case.block);
                assert_eq!(fixed.0, [0x37; 32]);
                assert_eq!(fixed.0, random.0);
            }
        }
    }

    #[test]
    fn all_routes_produce_one_block_and_match_cached() {
        let case = &corpus(0)[WARMUP];
        for trial in [aes128 as Trial, aes192 as Trial, aes256 as Trial] {
            for class in 0..2 {
                for mode in MODES {
                    let (key, block) = inputs(case, mode, class);
                    let a = trial("ephemeral", mode, &key, &block, false).unwrap().1;
                    let b = trial("cached", mode, &key, &block, false).unwrap().1;
                    assert_eq!(a.len(), 32);
                    assert_eq!(a, b);
                }
                let (key, block) = inputs(case, "import-key", class);
                assert_eq!(
                    trial("cached-import", "import-key", &key, &block, false)
                        .unwrap()
                        .1,
                    trial("cached", "encrypt-key", &key, &block, false)
                        .unwrap()
                        .1
                );
            }
        }
    }

    #[test]
    fn malformed_configurations_fail_before_measurement() {
        assert!(run("unknown").is_err());
        for trial in [aes128 as Trial, aes192 as Trial, aes256 as Trial] {
            for (owner, mode) in [
                ("unknown", "encrypt-key"),
                ("cached", "unknown"),
                ("cached-import", "encrypt-key"),
                ("ephemeral", "import-key"),
            ] {
                assert!(trial(owner, mode, &[0; 32], &[0; 16], true).is_err());
            }
        }
    }
}
