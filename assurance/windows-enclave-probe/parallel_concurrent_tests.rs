use super::*;
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
fn cleared(batch: &Batch<'_>) {
    assert_eq!(batch.phase, Phase::Dead);
    assert!(batch.slots.iter().all(Slot::cleared));
    assert_eq!(batch.output, [0; 1024]);
}
#[allow(clippy::too_many_arguments)] // Direct independent oracle row, test-only.
fn run_case(
    id: u64,
    block: usize,
    custom: &[u8],
    custom_bits: usize,
    input: &[u8],
    input_bits: usize,
    expected: &[u8],
    last: u8,
    threaded: bool,
) {
    let output_bits = if expected.is_empty() {
        0
    } else {
        (expected.len() - 1) * 8 + usize::from(last)
    };
    let plan = Plan::new(id, block, input_bits, custom_bits, output_bits).unwrap();
    let root = authority();
    let mut batch = Batch::new(&plan, &root).unwrap();
    let workers = batch.workers().unwrap();
    if threaded && !workers.is_empty() {
        let barrier = Barrier::new(workers.len());
        let creator = std::thread::current().id();
        std::thread::scope(|scope| {
            for (index, slot) in workers.iter_mut().enumerate() {
                let count = plan.leaf_bits(index).unwrap();
                let part = &input[index * block..index * block + count.div_ceil(8)];
                let barrier = &barrier;
                scope.spawn(move || {
                    assert_ne!(std::thread::current().id(), creator);
                    let local = authority();
                    barrier.wait();
                    slot.run(&local, bits(part, count)).unwrap();
                });
            }
        });
    } else {
        for (index, slot) in workers.iter_mut().enumerate().rev() {
            let count = plan.leaf_bits(index).unwrap();
            let part = &input[index * block..index * block + count.div_ceil(8)];
            slot.run(&authority(), bits(part, count)).unwrap();
        }
    }
    batch.finish(bits(custom, custom_bits)).unwrap();
    assert!(
        batch
            .slots
            .iter()
            .all(|slot| slot.cleared() || slot.unused())
    );
    assert_eq!(&batch.output[..expected.len()], expected);
    assert!(batch.output[expected.len()..].iter().all(|byte| *byte == 0));
    let mut output = std::vec![0xa5; expected.len()];
    batch.declassify_to(&mut output).unwrap();
    assert_eq!(
        output, expected,
        "id={id} B={block} bits={input_bits} threaded={threaded}"
    );
    cleared(&batch);
    assert_eq!(batch.declassify_to(&mut output), Err(Error::State));
    assert_eq!(output, expected);
}
#[test]
fn independent_oracle_reverse_and_real_scoped_workers() {
    let mut count = 0;
    for line in include_str!("parallel-concurrent-vectors.txt").lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 9);
        assert_eq!(fields[0], "D");
        for threaded in [false, true] {
            run_case(
                fields[1].parse().unwrap(),
                fields[2].parse().unwrap(),
                &decode(fields[6]),
                fields[3].parse().unwrap(),
                &decode(fields[7]),
                fields[4].parse().unwrap(),
                &decode(fields[8]),
                fields[5].parse().unwrap(),
                threaded,
            );
        }
        count += 1;
    }
    assert!(count >= 200, "oracle coverage unexpectedly shrank: {count}");
    std::println!("PARALLEL_CONCURRENT_ORACLE: {count} cases; reverse and scoped-thread modes");
}
#[test]
fn complete_plan_shape_boundaries() {
    for id in [0, 5, u64::MAX] {
        assert!(Plan::new(id, 1, 0, 0, 0).is_err());
    }
    for (block, input, custom, output) in [
        (0, 0, 0, 0),
        (1025, 0, 0, 0),
        (1, 33, 0, 0),
        (1024, 32769, 0, 0),
        (1, usize::MAX, 0, 0),
        (1, 0, 8193, 0),
        (1, 0, 0, 8193),
    ] {
        assert!(Plan::new(1, block, input, custom, output).is_err());
    }
    let plan = Plan::new(1, 1024, 32768, 8192, 8192).unwrap();
    assert_eq!(plan.leaf_bits(3), Ok(8192));
    assert_eq!(plan.leaf_bits(4), Err(Error::Length));
}
#[test]
fn wrong_length_duplicate_and_missing_leaf_clear_every_slot() {
    for id in 1..=4 {
        for variant in 0..3 {
            let plan = Plan::new(id, 1, 16, 0, 259).unwrap();
            let root = authority();
            let mut batch = Batch::new(&plan, &root).unwrap();
            let slots = batch.workers().unwrap();
            slots[0].run(&authority(), bits(&[1], 8)).unwrap();
            match variant {
                0 => assert_eq!(
                    slots[1].run(&authority(), empty().unwrap()),
                    Err(Error::Bits)
                ),
                1 => assert_eq!(slots[0].run(&authority(), bits(&[1], 8)), Err(Error::State)),
                _ => {}
            }
            assert_eq!(batch.finish(empty().unwrap()), Err(Error::State));
            cleared(&batch);
        }
    }
}
#[test]
fn exact_plan_identity_and_order_are_required() {
    for foreign in [false, true] {
        let plan = Plan::new(1, 1, 16, 0, 256).unwrap();
        let other = Plan::new(1, 1, 16, 0, 256).unwrap();
        let root = authority();
        let mut a = Batch::new(&plan, &root).unwrap();
        let mut b = Batch::new(&other, &root).unwrap();
        for batch in [&mut a, &mut b] {
            for slot in batch.workers().unwrap() {
                slot.run(&authority(), bits(&[7], 8)).unwrap();
            }
        }
        if foreign {
            core::mem::swap(&mut a.slots[0], &mut b.slots[0]);
        } else {
            a.slots.swap(0, 1);
        }
        assert_eq!(a.finish(empty().unwrap()), Err(Error::State));
        cleared(&a);
    }
}
#[test]
fn cancellation_and_revocation_are_terminal_and_public_output_is_transactional() {
    for stage in 0..4 {
        let plan = Plan::new(1, 1, 8, 0, 256).unwrap();
        let root = authority();
        let mut batch = Batch::new(&plan, &root).unwrap();
        batch.workers().unwrap()[0]
            .run(&authority(), bits(&[1], 8))
            .unwrap();
        if stage < 2 {
            if stage == 0 {
                plan.cancel();
            } else {
                root.quarantine();
            }
            assert!(batch.finish(empty().unwrap()).is_err());
        } else {
            batch.finish(empty().unwrap()).unwrap();
            if stage == 2 {
                plan.cancel();
            } else {
                root.quarantine();
            }
            let mut public = [0xa5; 32];
            assert!(batch.declassify_to(&mut public).is_err());
            assert_eq!(public, [0xa5; 32]);
        }
        cleared(&batch);
    }
}
#[test]
fn worker_unwind_and_root_unwind_clear_computed_secret_outputs() {
    fn unwind() {
        panic!("injected after crypto, before publication");
    }
    let plan = Plan::new(1, 1, 8, 0, 256).unwrap();
    let root = authority();
    let mut batch = Batch::new(&plan, &root).unwrap();
    let slot = &mut batch.workers().unwrap()[0];
    slot.before_publish = Some(unwind);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            slot.run(&authority(), bits(&[1], 8)).unwrap();
        }))
        .is_err()
    );
    assert!(slot.cleared());
    assert!(batch.finish(empty().unwrap()).is_err());
    cleared(&batch);
    let plan = Plan::new(1, 1, 8, 0, 256).unwrap();
    let mut batch = Batch::new(&plan, &root).unwrap();
    batch.workers().unwrap()[0]
        .run(&authority(), bits(&[1], 8))
        .unwrap();
    batch.before_commit = Some(unwind);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            batch.finish(empty().unwrap()).unwrap();
        }))
        .is_err()
    );
    cleared(&batch);
}
#[test]
fn cancelled_workers_never_publish_and_wrong_public_shape_does_not_copy() {
    let plan = Plan::new(1, 1, 8, 0, 256).unwrap();
    let root = authority();
    let mut batch = Batch::new(&plan, &root).unwrap();
    let slots = batch.workers().unwrap();
    plan.cancel();
    assert_eq!(
        slots[0].run(&authority(), bits(&[1], 8)),
        Err(Error::Cancelled)
    );
    assert!(slots[0].cleared());
    assert!(batch.finish(empty().unwrap()).is_err());
    cleared(&batch);
    let plan = Plan::new(1, 1, 8, 0, 256).unwrap();
    let mut batch = Batch::new(&plan, &root).unwrap();
    batch.workers().unwrap()[0]
        .run(&authority(), bits(&[1], 8))
        .unwrap();
    batch.finish(empty().unwrap()).unwrap();
    let mut output = [0xa5; 31];
    assert_eq!(batch.declassify_to(&mut output), Err(Error::Length));
    assert_eq!(output, [0xa5; 31]);
    cleared(&batch);
}
#[test]
fn root_cannot_finish_before_distribution_and_cancel_clears_retained_result() {
    let plan = Plan::new(1, 1, 0, 0, 256).unwrap();
    let root = authority();
    let mut batch = Batch::new(&plan, &root).unwrap();
    assert_eq!(batch.finish(empty().unwrap()), Err(Error::State));
    cleared(&batch);
    let plan = Plan::new(1, 1, 0, 0, 256).unwrap();
    let mut batch = Batch::new(&plan, &root).unwrap();
    assert!(batch.workers().unwrap().is_empty());
    batch.finish(empty().unwrap()).unwrap();
    batch.cancel();
    cleared(&batch);
    assert!(Batch::new(&plan, &root).is_err());
}

#[test]
fn plan_is_a_single_use_batch_identity_even_after_drop() {
    let plan = Plan::new(1, 1, 8, 0, 256).unwrap();
    let root = authority();
    let batch = Batch::new(&plan, &root).unwrap();
    assert!(matches!(Batch::new(&plan, &root), Err(Error::State)));
    drop(batch);
    assert!(matches!(Batch::new(&plan, &root), Err(Error::State)));
}

#[test]
fn cancellation_racing_four_scoped_workers_cannot_commit_output() {
    for _ in 0..16 {
        let plan = Plan::new(2, 1024, 32768, 0, 512).unwrap();
        let root = authority();
        let mut batch = Batch::new(&plan, &root).unwrap();
        let barrier = Barrier::new(5);
        std::thread::scope(|scope| {
            for slot in batch.workers().unwrap() {
                let barrier = &barrier;
                scope.spawn(move || {
                    let local = authority();
                    barrier.wait();
                    assert!(matches!(
                        slot.run(&local, bits(&[91; 1024], 8192)),
                        Ok(()) | Err(Error::Cancelled)
                    ));
                });
            }
            barrier.wait();
            plan.cancel();
        });
        assert_eq!(batch.finish(empty().unwrap()), Err(Error::Cancelled));
        cleared(&batch);
    }
}

#[test]
fn unused_slots_customization_and_redistribution_fail_closed() {
    for variant in 0..3 {
        let plan = Plan::new(1, 1, 8, 0, 256).unwrap();
        let root = authority();
        let mut batch = Batch::new(&plan, &root).unwrap();
        batch.workers().unwrap()[0]
            .run(&authority(), bits(&[1], 8))
            .unwrap();
        match variant {
            0 => {
                assert_eq!(
                    batch.slots[1].run(&authority(), empty().unwrap()),
                    Err(Error::Length)
                );
                assert_eq!(batch.finish(empty().unwrap()), Err(Error::State));
            }
            1 => assert_eq!(batch.finish(bits(&[1], 1)), Err(Error::Bits)),
            _ => assert!(matches!(batch.workers(), Err(Error::State))),
        }
        cleared(&batch);
    }
}

#[test]
fn revoked_worker_authority_cannot_publish_a_leaf() {
    let plan = Plan::new(1, 1, 8, 0, 256).unwrap();
    let root = authority();
    let mut batch = Batch::new(&plan, &root).unwrap();
    let local = authority();
    local.quarantine();
    let slot = &mut batch.workers().unwrap()[0];
    assert_eq!(slot.run(&local, bits(&[1], 8)), Err(Error::Backend));
    assert!(slot.cleared());
    assert_eq!(batch.finish(empty().unwrap()), Err(Error::State));
    cleared(&batch);
}
