use super::*;
use crate::{Batch, Kernel};
use std::sync::Barrier;
use std::vec::Vec;

fn authority() -> Authority {
    Authority::new(Kernel::X86Keccak).unwrap()
}
fn bits(bytes: &[u8], count: usize) -> Bits<'_> {
    Bits::new(
        bytes,
        if count == 0 {
            0
        } else {
            ((count - 1) % 8 + 1) as u8
        },
    )
    .unwrap()
}
fn decode(text: &str) -> Vec<u8> {
    if text == "-" {
        return Vec::new();
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn cleared(root: &Waves<'_>) {
    assert_eq!(root.phase, Phase::Dead);
    assert!(matches!(root.state, State::Empty));
    assert_eq!(root.output, [0; 1024]);
}
fn fill(offset: usize, block: usize, plan: &Plan, slots: &mut [Slot<'_>], input: &[u8]) {
    for (lane, slot) in slots.iter_mut().enumerate().rev() {
        let count = plan.leaf_bits(lane).unwrap();
        let start = offset + lane * block;
        slot.run(
            &authority(),
            bits(&input[start..start + count.div_ceil(8)], count),
        )
        .unwrap();
    }
}
#[test]
fn independent_multi_wave_bit_oracle_reverse_and_scoped_workers() {
    let mut count = 0;
    for line in include_str!("parallel-waves-vectors.txt").lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        let id = fields[1].parse().unwrap();
        let block: usize = fields[2].parse().unwrap();
        let custom_bits = fields[3].parse().unwrap();
        let input_bits = fields[4].parse().unwrap();
        let last: usize = fields[5].parse().unwrap();
        let custom = decode(fields[6]);
        let input = decode(fields[7]);
        let expected = decode(fields[8]);
        let output_bits = if expected.is_empty() {
            0
        } else {
            (expected.len() - 1) * 8 + last
        };
        for threaded in [false, true] {
            let local = authority();
            let mut root = Waves::new(
                &local,
                id,
                block,
                input_bits,
                bits(&custom, custom_bits),
                output_bits,
            )
            .unwrap();
            let mut offset_expected = 0;
            while root.consumed_bits < input_bits {
                root.wave(|offset, plan, slots| {
                    assert_eq!(offset, offset_expected);
                    assert!(matches!(Batch::new(plan, &local), Err(Error::State)));
                    if threaded {
                        let barrier = Barrier::new(slots.len());
                        std::thread::scope(|scope| {
                            for (lane, slot) in slots.iter_mut().enumerate() {
                                let count = plan.leaf_bits(lane).unwrap();
                                let start = offset + lane * block;
                                let part = &input[start..start + count.div_ceil(8)];
                                let barrier = &barrier;
                                scope.spawn(move || {
                                    let local = authority();
                                    barrier.wait();
                                    slot.run(&local, bits(part, count)).unwrap();
                                });
                            }
                        });
                    } else {
                        fill(offset, block, plan, slots, &input);
                    }
                    offset_expected += (input_bits - offset * 8).min(block * 32).div_ceil(8);
                    Ok(())
                })
                .unwrap();
            }
            assert_eq!(root.merged_leaves, input_bits.div_ceil(block * 8));
            root.finish().unwrap();
            let mut output = std::vec![0xa5; expected.len()];
            root.declassify_to(&mut output).unwrap();
            assert_eq!(
                output, expected,
                "identity={id} B={block} input_bits={input_bits} threaded={threaded}"
            );
            cleared(&root);
        }
        count += 1;
    }
    assert!(count >= 400);
    std::println!("MULTI_WAVE_PARALLELHASH_ORACLE: {count} cases x two scheduling orders");
}

#[test]
fn every_incomplete_wave_and_finalization_rejects_and_clears() {
    for id in 1..=4 {
        for missing in 0..4 {
            let local = authority();
            let mut root = Waves::new(&local, id, 1, 72, empty().unwrap(), 256).unwrap();
            root.wave(|offset, plan, slots| {
                fill(offset, 1, plan, slots, &[5; 9]);
                Ok(())
            })
            .unwrap();
            assert_eq!(
                root.wave(|offset, plan, slots| {
                    for (lane, slot) in slots.iter_mut().enumerate() {
                        if lane != missing {
                            slot.run(&authority(), bits(&[5], plan.leaf_bits(lane)?))?;
                        }
                    }
                    assert_eq!(offset, 4);
                    Ok(())
                }),
                Err(Error::State)
            );
            cleared(&root);
        }
        for completed in 0..3 {
            let local = authority();
            let mut root = Waves::new(&local, id, 1, 73, empty().unwrap(), 256).unwrap();
            for _ in 0..completed {
                root.wave(|offset, plan, slots| {
                    fill(offset, 1, plan, slots, &[0; 10]);
                    Ok(())
                })
                .unwrap();
            }
            assert_eq!(root.finish(), Err(Error::State));
            cleared(&root);
        }
    }
}

#[test]
fn callback_error_cancellation_and_unwind_after_a_complete_wave_are_terminal() {
    for mode in 0..4 {
        let local = authority();
        let mut root = Waves::new(&local, 1, 1, 64, empty().unwrap(), 256).unwrap();
        root.wave(|offset, plan, slots| {
            fill(offset, 1, plan, slots, &[0; 8]);
            Ok(())
        })
        .unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            root.wave(|offset, plan, slots| {
                fill(offset, 1, plan, slots, &[0; 8]);
                match mode {
                    0 => Err(Error::Crypto),
                    1 => {
                        plan.cancel();
                        Ok(())
                    }
                    2 => {
                        local.quarantine();
                        Ok(())
                    }
                    _ => panic!("after computing wave before root absorbs it"),
                }
            })
        }));
        if mode == 3 {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        cleared(&root);
        assert_eq!(
            root.wave(|_, _, _| panic!("terminal callback")),
            Err(Error::State)
        );
        let mut output = [0xa5; 32];
        assert_eq!(root.declassify_to(&mut output), Err(Error::State));
        assert_eq!(output, [0xa5; 32]);
    }
}

#[test]
fn exact_completion_and_counter_corruption_fail_closed() {
    for mode in 0..4 {
        let local = authority();
        let mut root = Waves::new(&local, 1, 1, 40, empty().unwrap(), 256).unwrap();
        root.wave(|offset, plan, slots| {
            fill(offset, 1, plan, slots, &[0; 5]);
            Ok(())
        })
        .unwrap();
        match mode {
            0 => root.merged_leaves = usize::MAX,
            1 => root.consumed_bits = 31,
            2 => root.expected_leaves = 4,
            _ => root.total_bits = 31,
        }
        assert!(
            root.wave(|offset, plan, slots| {
                fill(offset, 1, plan, slots, &[0; 5]);
                Ok(())
            })
            .is_err()
        );
        cleared(&root);
    }
    for field in 0..2 {
        let local = authority();
        let mut root = Waves::new(&local, 1, 1, 8, empty().unwrap(), 256).unwrap();
        root.wave(|offset, plan, slots| {
            fill(offset, 1, plan, slots, &[0]);
            Ok(())
        })
        .unwrap();
        if field == 0 {
            root.merged_leaves = 0;
        } else {
            root.consumed_bits = 7;
        }
        assert_eq!(root.finish(), Err(Error::State));
        cleared(&root);
    }
}

#[test]
fn revocation_output_shape_and_finish_unwind_clear_retained_bytes() {
    for mode in 0..5 {
        let local = authority();
        let mut root = Waves::new(&local, 4, 1, 0, empty().unwrap(), 256).unwrap();
        if mode == 4 {
            root.before_commit = Some(|| panic!("retained output before commit"));
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| root.finish())).is_err()
            );
        } else {
            root.finish().unwrap();
            match mode {
                0 => {
                    local.quarantine();
                    let mut out = [0xa5; 32];
                    assert_eq!(root.declassify_to(&mut out), Err(Error::Backend));
                    assert_eq!(out, [0xa5; 32]);
                }
                1 => {
                    let mut out = [0xa5; 31];
                    assert_eq!(root.declassify_to(&mut out), Err(Error::Length));
                    assert_eq!(out, [0xa5; 31]);
                }
                2 => assert_eq!(root.finish(), Err(Error::State)),
                _ => root.cancel(),
            }
        }
        cleared(&root);
    }
}

#[test]
fn reordered_and_replayed_slots_cannot_be_reduced() {
    for reorder in [false, true] {
        let local = authority();
        let mut root = Waves::new(&local, 1, 1, 32, empty().unwrap(), 256).unwrap();
        assert_eq!(
            root.wave(|offset, plan, slots| {
                fill(offset, 1, plan, slots, &[3; 4]);
                if reorder {
                    slots.swap(0, 1);
                } else {
                    assert_eq!(slots[0].run(&authority(), bits(&[3], 8)), Err(Error::State));
                }
                Ok(())
            }),
            Err(Error::State)
        );
        cleared(&root);
    }
}

#[test]
fn exact_private_work_bounds_and_empty_input() {
    let local = authority();
    for count in [0, 1, MAX_LEAVES * 8] {
        assert!(Waves::new(&local, 1, 1, count, empty().unwrap(), 0).is_ok());
    }
    for count in [MAX_LEAVES * 8 + 1, usize::MAX] {
        assert!(matches!(
            Waves::new(&local, 1, 1, count, empty().unwrap(), 0),
            Err(Error::Length)
        ));
    }
    for id in [0, 5] {
        assert!(matches!(
            Waves::new(&local, id, 1, 0, empty().unwrap(), 0),
            Err(Error::Identity)
        ));
    }
    for block in [0, 1025, usize::MAX] {
        assert!(matches!(
            Waves::new(&local, 1, block, 0, empty().unwrap(), 0),
            Err(Error::Length)
        ));
    }
    for output in [8193, usize::MAX] {
        assert!(matches!(
            Waves::new(&local, 1, 1, 0, empty().unwrap(), output),
            Err(Error::Length)
        ));
    }
    assert!(matches!(
        Waves::new(&local, 1, 1, 0, bits(&[0; 1025], 8200), 0),
        Err(Error::Length)
    ));
    assert!(Waves::new(&local, 1, 1, 0, bits(&[0; 1024], 8192), 8192).is_ok());
    let mut root = Waves::new(&local, 1, 1, 0, empty().unwrap(), 0).unwrap();
    root.finish().unwrap();
    root.declassify_to(&mut []).unwrap();
    cleared(&root);
}

#[test]
fn no_extra_wave_after_exact_input_and_no_callback_after_revocation() {
    let local = authority();
    let mut root = Waves::new(&local, 1, 1, 8, empty().unwrap(), 256).unwrap();
    root.wave(|offset, plan, slots| {
        fill(offset, 1, plan, slots, &[0]);
        Ok(())
    })
    .unwrap();
    assert_eq!(
        root.wave(|_, _, _| panic!("no extra wave")),
        Err(Error::State)
    );
    cleared(&root);
    let mut root = Waves::new(&local, 1, 1, 8, empty().unwrap(), 256).unwrap();
    local.quarantine();
    assert_eq!(
        root.wave(|_, _, _| panic!("no revoked callback")),
        Err(Error::Backend)
    );
    cleared(&root);
}

#[test]
fn cancellation_races_scoped_workers_at_each_wave_boundary() {
    for stop in 0..3 {
        let local = authority();
        let mut root = Waves::new(&local, 1, 1, 72, empty().unwrap(), 256).unwrap();
        for _ in 0..stop {
            root.wave(|offset, plan, slots| {
                fill(offset, 1, plan, slots, &[0; 9]);
                Ok(())
            })
            .unwrap();
        }
        assert_eq!(
            root.wave(|_, plan, slots| {
                let barrier = Barrier::new(slots.len() + 1);
                std::thread::scope(|scope| {
                    for slot in slots {
                        let barrier = &barrier;
                        scope.spawn(move || {
                            let local = authority();
                            barrier.wait();
                            assert!(matches!(
                                slot.run(&local, bits(&[0], 8)),
                                Ok(()) | Err(Error::Cancelled)
                            ));
                        });
                    }
                    barrier.wait();
                    plan.cancel();
                });
                Ok(())
            }),
            Err(Error::Cancelled)
        );
        cleared(&root);
    }
}
