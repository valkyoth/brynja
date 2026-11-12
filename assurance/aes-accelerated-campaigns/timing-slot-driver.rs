//! Integration with the original cached trial; no replacement AES or timer.
use super::*;

const CONTROLS: [&str; 2] = ["values", "identical"];

fn campaigns() -> [(usize, &'static str, usize, Trial); 3] {
    [
        (192, "decrypt-block", 22, aes192 as Trial),
        (256, "public-block", 37, aes256 as Trial),
        (256, "public-key", 36, aes256 as Trial),
    ]
}

fn remember_address(
    addresses: &mut [Option<(usize, usize)>; 2],
    slot: usize,
    key: &[u8; 32],
    block: &[u8; 16],
) -> Result<()> {
    let entry = addresses.get_mut(slot).ok_or("unknown crossover slot")?;
    let actual = (key.as_ptr() as usize, block.as_ptr() as usize);
    if entry.is_some_and(|previous| previous != actual) {
        return Err("crossover input address changed".into());
    }
    *entry = Some(actual);
    Ok(())
}

pub fn run(phase: &str) -> Result<()> {
    if !matches!(phase, "crossover-preflight" | "crossover-measure") {
        return Err("unknown crossover phase".into());
    }
    let measuring = phase == "crossover-measure";
    let forced = brynja_aes_accelerated_fixture::forced_authority().map_err(|e| e.to_string())?;
    let authority = forced.get().map_err(|e| e.to_string())?;
    println!(
        "AES_SLOT_CROSSOVER_POLICY {SAMPLES} {REPEAT} {WARMUP} {SEED} {}",
        slot_crossover::ORDER_SEED
    );
    for (bits, mode, campaign, trial) in campaigns() {
        let cases = corpus(campaign as u64);
        let order = slot_crossover::patterns(campaign as u64);
        for control in CONTROLS {
            let mut slots = slot_crossover::Slots::default();
            let mut addresses = [None; 2];
            let mut records = Vec::with_capacity(SAMPLES);
            if measuring {
                for (index, (case, &pattern)) in cases.iter().zip(&order).enumerate() {
                    let fixed = inputs(case, mode, 0);
                    let random = if control == "identical" {
                        fixed
                    } else {
                        inputs(case, mode, 1)
                    };
                    let values = [fixed, random];
                    let elapsed =
                        black_box(&mut slots).round(&values, pattern, |_, slot, key, block| {
                            // Address checks and cell bookkeeping precede the trial's
                            // clock. Class/slot are not arguments to the AES trial.
                            remember_address(&mut addresses, slot, key, block)?;
                            Ok(trial(authority, "cached", mode, key, block, true)?.0)
                        })?;
                    if index >= WARMUP {
                        records.push(elapsed);
                    }
                }
                for (slot, address) in addresses.into_iter().enumerate() {
                    let (key, block) = address.ok_or("missing crossover address")?;
                    println!("SLOT {bits} {mode} {control} {slot} {key} {block}");
                }
                for (sample, elapsed) in records.iter().enumerate() {
                    let pattern = order[WARMUP + sample];
                    println!(
                        "CROSS_SAMPLE {bits} {mode} {control} {sample} {pattern} {} {} {} {}",
                        elapsed[0], elapsed[1], elapsed[2], elapsed[3]
                    );
                }
            } else {
                for sample in [0, SAMPLES / 2, SAMPLES - 1] {
                    let case = &cases[WARMUP + sample];
                    let fixed = inputs(case, mode, 0);
                    let random = if control == "identical" {
                        fixed
                    } else {
                        inputs(case, mode, 1)
                    };
                    for pattern in 0..8 {
                        black_box(&mut slots).round(&[fixed, random], pattern, |class, slot, key, block| {
                            remember_address(&mut addresses, slot, key, block)?;
                            let (_, hex) = trial(authority, "cached", mode, key, block, false)?;
                            println!("CROSS_VECTOR {bits} {mode} {control} {sample} {pattern} {class} {slot} {hex}");
                            Ok(0)
                        })?;
                    }
                }
            }
        }
    }
    println!("AES_SLOT_CROSSOVER_END {phase}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_phase_fails_before_authority() {
        assert!(run("measure").is_err());
        assert!(run("crossover").is_err());
    }

    #[test]
    fn corpus_ids_match_original_campaigns() {
        let mut ids = Vec::new();
        for bits in [128, 192, 256] {
            for owner in ["ephemeral", "cached", "cached-import"] {
                let modes: &[&str] = if owner == "cached-import" {
                    &["import-key"]
                } else {
                    &MODES
                };
                for mode in modes {
                    ids.push((bits, owner, *mode));
                }
            }
        }
        for (bits, mode, index, _) in campaigns() {
            assert_eq!(ids[index], (bits, "cached", mode));
        }
        assert_eq!(SAMPLES, slot_crossover::SAMPLES);
        assert_eq!(WARMUP, slot_crossover::WARMUP);
    }

    #[test]
    fn address_drift_and_invalid_slots_fail() {
        let keys = [[1; 32], [2; 32]];
        let blocks = [[3; 16], [4; 16]];
        let mut addresses = [None; 2];
        remember_address(&mut addresses, 0, &keys[0], &blocks[0]).unwrap();
        remember_address(&mut addresses, 0, &keys[0], &blocks[0]).unwrap();
        assert!(remember_address(&mut addresses, 0, &keys[1], &blocks[0]).is_err());
        assert!(remember_address(&mut addresses, 0, &keys[0], &blocks[1]).is_err());
        assert!(remember_address(&mut addresses, 2, &keys[0], &blocks[0]).is_err());
    }
}
