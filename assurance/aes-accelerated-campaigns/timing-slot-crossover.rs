//! Test-only class/address crossover. No AES implementation or clock calls.
#![forbid(unsafe_code)]

use std::hint::black_box;

pub type Input = ([u8; 32], [u8; 16]);
pub const SAMPLES: usize = 8192;
pub const WARMUP: usize = 256;
pub const ORDER_SEED: u64 = 0x0273_c205_50fe_0001;

// Public reproducible scheduling only; this is not a cryptographic generator.
fn next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

/// Each eight-way pattern occurs equally often in warmup and retained rounds.
/// Shuffle those sections separately before calling any measurement function.
pub fn patterns(campaign: u64) -> Vec<u8> {
    let mut state = ORDER_SEED ^ campaign;
    let mut result = Vec::with_capacity(WARMUP + SAMPLES);
    for count in [WARMUP, SAMPLES] {
        let mut section: Vec<u8> = (0..count).map(|i| (i % 8) as u8).collect();
        for end in (1..count).rev() {
            let chosen = (next(&mut state) % (end as u64 + 1)) as usize;
            section.swap(end, chosen);
        }
        result.extend(section);
    }
    result
}

/// Tuple: (mapping, first class). Class zero occupies slot `mapping`.
/// Bit zero selects mapping order; the other bits select each stage's order.
pub fn stages(pattern: u8) -> Result<[(usize, usize); 2], String> {
    if pattern >= 8 {
        return Err("invalid crossover pattern".into());
    }
    let mapping = usize::from(pattern & 1);
    Ok([
        (mapping, usize::from((pattern >> 1) & 1)),
        (1 - mapping, usize::from((pattern >> 2) & 1)),
    ])
}

#[derive(Default)]
pub struct Slots {
    inputs: [Input; 2],
}

impl Slots {
    /// One round invokes each (class, slot) cell exactly once. The operation
    /// starts/stops its own timer, so materialization and cell bookkeeping are
    /// outside that timer. Errors stop the round; callers must retain failure.
    ///
    /// The returned order is fixed0, fixed1, random0, random1, regardless of
    /// execution order. Keep this owner at one address for the whole campaign.
    #[inline(never)]
    pub fn round(
        &mut self,
        inputs: &[Input; 2],
        pattern: u8,
        mut operation: impl FnMut(usize, usize, &[u8; 32], &[u8; 16]) -> Result<u128, String>,
    ) -> Result<[u128; 4], String> {
        let stages = stages(pattern)?;
        let mut elapsed = [0; 4];
        for (mapping, first) in stages {
            // Both slots are written on both stages, regardless of class/order.
            // Original class inputs never become the operation's input pointers.
            let slots = black_box(&mut self.inputs);
            // Write in slot order, not class order: neither value class is
            // always the most recently materialized one.
            for (slot, destination) in slots.iter_mut().enumerate() {
                let source = &inputs[slot ^ mapping];
                destination.0.copy_from_slice(black_box(&source.0));
                destination.1.copy_from_slice(black_box(&source.1));
            }
            for class in [first, 1 - first] {
                let slot = class ^ mapping;
                let selected = black_box(&slots[slot]);
                elapsed[class * 2 + slot] =
                    operation(class, slot, black_box(&selected.0), black_box(&selected.1))?;
            }
        }
        Ok(elapsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_are_balanced_reproducible_and_campaign_separated() {
        let schedule = patterns(0);
        assert_eq!(schedule, patterns(0));
        assert_ne!(schedule, patterns(1));
        assert_eq!(schedule.len(), WARMUP + SAMPLES);
        // Public schedule regression vectors, independently replayed by Python.
        // FNV here is only a compact test checksum, not an authenticity claim.
        for (campaign, expected) in [
            (22, 0x9bfc_8429_a8dc_dd83),
            (37, 0x26aa_7570_5d94_d25b),
            (36, 0x3be3_a5b4_f308_420d),
        ] {
            let checksum = patterns(campaign)
                .iter()
                .fold(0xcbf2_9ce4_8422_2325u64, |h, &p| {
                    (h ^ u64::from(p)).wrapping_mul(0x100_0000_01b3)
                });
            assert_eq!(checksum, expected);
        }
        for section in [&schedule[..WARMUP], &schedule[WARMUP..]] {
            for pattern in 0..8 {
                assert_eq!(
                    section.iter().filter(|&&p| p == pattern).count(),
                    section.len() / 8
                );
            }
        }
    }

    #[test]
    fn every_pattern_visits_every_cell_once_with_correct_values() {
        let inputs = [([7; 32], [8; 16]), ([9; 32], [10; 16])];
        let mut slots = Slots::default();
        for pattern in 0..8 {
            let mut seen = [0; 4];
            let mut order = Vec::new();
            let result = slots
                .round(&inputs, pattern, |class, slot, key, block| {
                    assert_eq!((*key, *block), inputs[class]);
                    let cell = class * 2 + slot;
                    seen[cell] += 1;
                    order.push((class, slot));
                    Ok(cell as u128 + 100)
                })
                .unwrap();
            assert_eq!(seen, [1; 4]);
            assert_eq!(result, [100, 101, 102, 103]);
            let expected: Vec<_> = stages(pattern)
                .unwrap()
                .into_iter()
                .flat_map(|(mapping, first)| {
                    [first, 1 - first].map(|class| (class, class ^ mapping))
                })
                .collect();
            assert_eq!(order, expected);
        }
    }

    #[test]
    fn slot_addresses_stay_fixed_when_classes_and_rounds_change() {
        let mut slots = Slots::default();
        let mut addresses = [None; 2];
        for pattern in patterns(0) {
            let inputs = [([pattern; 32], [0; 16]), ([255 - pattern; 32], [255; 16])];
            slots
                .round(&inputs, pattern, |class, slot, key, block| {
                    let actual = (key.as_ptr() as usize, block.as_ptr() as usize);
                    if let Some(previous) = addresses[slot] {
                        assert_eq!(actual, previous);
                    }
                    addresses[slot] = Some(actual);
                    assert_ne!(actual.0, inputs[class].0.as_ptr() as usize);
                    assert_ne!(actual.1, inputs[class].1.as_ptr() as usize);
                    assert_eq!((*key, *block), inputs[class]);
                    Ok(1)
                })
                .unwrap();
        }
        assert_ne!(addresses[0], addresses[1]);
        assert_eq!(
            addresses[0].unwrap().0.abs_diff(addresses[1].unwrap().0),
            48
        );
        assert_eq!(
            addresses[0].unwrap().1.abs_diff(addresses[1].unwrap().1),
            48
        );
    }

    #[test]
    fn identical_input_control_preserves_labels_but_equalizes_values() {
        let inputs = [([3; 32], [4; 16]); 2];
        let mut slots = Slots::default();
        for pattern in 0..8 {
            let result = slots
                .round(&inputs, pattern, |class, slot, key, block| {
                    assert_eq!((*key, *block), inputs[0]);
                    Ok((class * 2 + slot) as u128)
                })
                .unwrap();
            assert_eq!(result, [0, 1, 2, 3]);
        }
    }

    #[test]
    fn invalid_patterns_do_not_call_the_operation() {
        for pattern in 8..=255 {
            assert!(
                Slots::default()
                    .round(&[([0; 32], [0; 16]); 2], pattern, |_, _, _, _| panic!(
                        "must not execute"
                    ))
                    .is_err()
            );
        }
    }

    #[test]
    fn every_failure_position_stops_without_retry_or_later_cells() {
        for failure in 0..4 {
            let mut calls = 0;
            let result = Slots::default().round(&[([0; 32], [0; 16]); 2], 0, |_, _, _, _| {
                let position = calls;
                calls += 1;
                if position == failure {
                    Err("injected".into())
                } else {
                    Ok(1)
                }
            });
            assert_eq!(result, Err("injected".into()));
            assert_eq!(calls, failure + 1);
        }
    }
}
