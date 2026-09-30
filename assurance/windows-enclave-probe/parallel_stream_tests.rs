use super::*;
use std::vec::Vec;
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
fn fragment(input: &[u8], start: usize, count: usize) -> Vec<u8> {
    let mut out = std::vec![0; count.div_ceil(8)];
    for i in 0..count {
        out[i / 8] |= ((input[(start + i) / 8] >> ((start + i) % 8)) & 1) << (i % 8);
    }
    out
}
fn check_case(
    id: u64,
    block: u64,
    custom: &[u8],
    custom_bits: usize,
    input: &[u8],
    input_bits: usize,
    expected: &[u8],
    last: u8,
) {
    let mut owner = Owner::new();
    let mut sequence = 1;
    owner
        .begin(sequence, id, block, custom_bits as u128, u64::MAX)
        .unwrap();
    let mut position = 0;
    while position < custom_bits {
        let count = (custom_bits - position).min(if position == 0 { 3 } else { 8183 });
        let piece = fragment(custom, position, count);
        sequence += 1;
        owner.custom(sequence, bits(&piece, count)).unwrap();
        position += count;
    }
    sequence += 1;
    owner.finish_custom(sequence).unwrap();
    sequence += 1;
    owner.update(sequence, &[]).unwrap();
    let complete = input_bits / 8;
    for chunk in input[..complete].chunks(113) {
        sequence += 1;
        owner.update(sequence, chunk).unwrap();
    }
    sequence += 1;
    let tail = bits(&input[complete..], input_bits % 8);
    owner
        .finish(
            sequence,
            tail,
            if id <= 2 { expected.len() } else { 0 },
            if id <= 2 { last } else { 0 },
        )
        .unwrap();
    let mut result = Vec::new();
    if id > 2 {
        let mut left = expected.len();
        while left > 31 {
            sequence += 1;
            owner.squeeze(sequence, 31, 8, false).unwrap();
            sequence += 1;
            owner
                .export(sequence, id, 31, 8, |x| {
                    result.extend_from_slice(x);
                    true
                })
                .unwrap();
            left -= 31;
        }
        sequence += 1;
        owner.squeeze(sequence, left, last, true).unwrap();
        sequence += 1;
        owner
            .export(sequence, id, left, last, |x| {
                result.extend_from_slice(x);
                true
            })
            .unwrap();
    } else {
        sequence += 1;
        owner
            .export(sequence, id, expected.len(), last, |x| {
                result.extend_from_slice(x);
                true
            })
            .unwrap();
    }
    assert_eq!(
        result, expected,
        "id={id} block={block} input_bits={input_bits}"
    );
    cleared(&owner, Phase::Empty);
}
fn started(id: u64, block: u64, budget: u64) -> Owner {
    let mut o = Owner::new();
    o.begin(1, id, block, 0, budget).unwrap();
    o.finish_custom(2).unwrap();
    o
}
fn retained(id: u64) -> Owner {
    let mut o = started(id, 8, 3);
    o.update(3, b"abc").unwrap();
    o.finish(
        4,
        empty().unwrap(),
        if id <= 2 { 32 } else { 0 },
        if id <= 2 { 8 } else { 0 },
    )
    .unwrap();
    if id > 2 {
        o.squeeze(5, 32, 8, false).unwrap();
    }
    o
}
fn cleared(o: &Owner, phase: Phase) {
    assert_eq!(o.phase, phase);
    assert!(matches!(o.root, State::Empty));
    assert!(o.input.cleared());
    assert_eq!(o.output, [0; 1024]);
    assert_eq!(o.budget, [0; 8]);
    assert_eq!((o.identity, o.block, o.width, o.last), (0, 0, 0, 0));
}
fn copy_failure_unwind_and_cancel(id: u64) {
    let next = if id <= 2 { 5 } else { 6 };
    let mut o = retained(id);
    assert_eq!(o.export(next, id, 32, 8, |_| false), Err(Error::Copy));
    cleared(&o, Phase::Quarantined);
    assert!(o.begin(next + 1, id, 8, 0, 8).is_err());
    let mut o = retained(id);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| o.export(
            next,
            id,
            32,
            8,
            |_| panic!("synthetic copy unwind")
        )))
        .is_err()
    );
    cleared(&o, Phase::Quarantined);
    let mut o = retained(id);
    o.cancel(next).unwrap();
    cleared(&o, Phase::Empty);
    o.begin(next + 1, id, 8, 0, 8).unwrap();
    o.cancel(next + 2).unwrap();
    cleared(&o, Phase::Empty);
}
#[test]
fn copy_failure_unwind_and_cancel_128() {
    copy_failure_unwind_and_cancel(1);
}
#[test]
fn copy_failure_unwind_and_cancel_256() {
    copy_failure_unwind_and_cancel(2);
}
#[test]
fn copy_failure_unwind_and_cancel_xof128() {
    copy_failure_unwind_and_cancel(3);
}
#[test]
fn copy_failure_unwind_and_cancel_xof256() {
    copy_failure_unwind_and_cancel(4);
}
#[test]
fn phases_sequences_shapes_and_export_identity_fail_closed() {
    for id in 1..=4 {
        let next = if id <= 2 { 5 } else { 6 };
        for (identity, width, last) in [(0, 32, 8), (id, 31, 8), (id, 32, 7)] {
            let mut o = retained(id);
            let mut called = false;
            assert!(
                o.export(next, identity, width, last, |_| {
                    called = true;
                    true
                })
                .is_err()
            );
            assert!(!called);
            cleared(&o, Phase::Quarantined);
        }
        let mut o = started(id, 8, 8);
        assert!(o.update(2, b"x").is_err());
        cleared(&o, Phase::Quarantined);
        let mut o = started(id, 8, 8);
        o.sequence = u64::MAX;
        assert!(o.update(0, b"x").is_err());
        cleared(&o, Phase::Quarantined);
        let mut o = started(id, 8, 8);
        assert!(o.finish_custom(3).is_err());
        cleared(&o, Phase::Quarantined);
    }
    for (width, last) in [(1025, 8), (0, 1), (1, 0), (1, 9)] {
        let mut o = started(1, 8, 8);
        assert!(o.finish(3, empty().unwrap(), width, last).is_err());
        cleared(&o, Phase::Quarantined);
    }
    let mut o = started(3, 8, 8);
    assert!(o.finish(3, empty().unwrap(), 1, 8).is_err());
    cleared(&o, Phase::Quarantined);
    let mut o = started(3, 8, 8);
    o.finish(3, empty().unwrap(), 0, 0).unwrap();
    assert!(o.squeeze(4, 1, 3, false).is_err());
    cleared(&o, Phase::Quarantined);
}
#[test]
fn incomplete_setup_budget_and_snapshot_bounds_reject() {
    for (identity, block) in [(0, 8), (5, 8), (1, 0)] {
        let mut o = Owner::new();
        assert!(o.begin(1, identity, block, 0, 8).is_err());
        cleared(&o, Phase::Quarantined);
    }
    let mut o = Owner::new();
    o.begin(1, 1, 8, 9, 8).unwrap();
    o.custom(2, bits(&[1], 8)).unwrap();
    assert!(o.finish_custom(3).is_err());
    cleared(&o, Phase::Quarantined);
    let mut o = Owner::new();
    o.begin(1, 1, 8, 0, 8).unwrap();
    assert!(o.custom(2, bits(&[1], 1)).is_err());
    cleared(&o, Phase::Quarantined);
    let mut o = Owner::new();
    o.begin(1, 1, 8, 8, 0).unwrap();
    assert!(o.custom(2, bits(&[1], 8)).is_err());
    cleared(&o, Phase::Quarantined);
    let mut o = started(1, 8, 0);
    assert!(o.update(3, b"x").is_err());
    cleared(&o, Phase::Quarantined);
    let mut o = started(1, 8, u64::MAX);
    assert!(o.update(3, &[1; 1025]).is_err());
    cleared(&o, Phase::Quarantined);
    let mut o = started(1, 8, u64::MAX);
    assert!(o.finish(3, bits(&[1; 1025], 8200), 32, 8).is_err());
    cleared(&o, Phase::Quarantined);
}
#[test]
fn exact_leaf_completion_and_counter_overflow_are_load_bearing() {
    let mut o = started(1, 8, 8);
    o.input.corrupt(0, 1, 0);
    assert!(o.finish(3, empty().unwrap(), 32, 8).is_err());
    cleared(&o, Phase::Quarantined);
    let mut o = started(1, 8, 8);
    o.input.corrupt(9, 0, 72);
    assert!(o.finish(3, empty().unwrap(), 32, 8).is_err());
    cleared(&o, Phase::Quarantined);
    let mut o = started(1, 8, 8);
    o.input.corrupt(0, 0, u128::MAX);
    assert!(o.update(3, b"x").is_err());
    cleared(&o, Phase::Quarantined);
    let mut o = started(1, 1, 8);
    o.input.corrupt(0, u128::MAX, 0);
    assert!(o.update(3, b"x").is_err());
    cleared(&o, Phase::Quarantined);
}
#[test]
fn positive_u64_block_sizes_do_not_allocate_the_block() {
    for id in 1..=4 {
        let mut a = started(id, u64::MAX, 3);
        a.update(3, b"abc").unwrap();
        a.finish(
            4,
            empty().unwrap(),
            if id <= 2 { 32 } else { 0 },
            if id <= 2 { 8 } else { 0 },
        )
        .unwrap();
        a.cancel(5).unwrap();
        cleared(&a, Phase::Empty);
    }
    assert!(core::mem::size_of::<Owner>() < 4096);
}
#[test]
fn integer_encodings_match_the_normative_helpers_and_erase() {
    for n in [0, 1, 255, 256, 65535, 65536, u64::MAX as u128, u128::MAX] {
        let mut e = SecretEncodedInteger::empty();
        e.left(n).unwrap();
        assert_eq!(
            e.bytes().unwrap(),
            brynja_hash_sha3::left_encode_u128(n).as_bytes()
        );
        e.right(n).unwrap();
        assert_eq!(
            e.bytes().unwrap(),
            brynja_hash_sha3::right_encode_u128(n).as_bytes()
        );
    }
}
