use super::*;
fn next(sequence: &mut u64) -> u64 {
    *sequence = sequence.checked_add(1).unwrap();
    *sequence
}
fn empty() -> Bits<'static> {
    Bits::new(&[], 0).unwrap()
}
fn slice_bits(input: &[u8], start: usize, count: usize) -> std::vec::Vec<u8> {
    let mut out = std::vec![0; count.div_ceil(8)];
    for i in 0..count {
        out[i / 8] |= ((input[(start + i) / 8] >> ((start + i) % 8)) & 1) << (i % 8);
    }
    out
}
pub(super) fn fragments(mut call: impl FnMut(Bits<'_>), input: &[u8], bitlen: usize) {
    // Misalign the stream then cross several snapshot/rate boundaries.
    let mut start = 0;
    for size in [3, 8192, 7, 4096].into_iter().cycle() {
        if start == bitlen {
            break;
        }
        let count = size.min(bitlen - start);
        let fragment = slice_bits(input, start, count);
        call(Bits::new(&fragment, ((count - 1) % 8 + 1) as u8).unwrap());
        start += count;
    }
}
fn setup(o: &mut Owner, seq: &mut u64, id: u64, custom: &[u8], bits: usize) {
    o.begin(next(seq), id, bits as u128).unwrap();
    fragments(|v| o.custom(next(seq), v).unwrap(), custom, bits);
    o.finish_custom(next(seq)).unwrap();
}
fn item(o: &mut Owner, seq: &mut u64, data: &[u8], bits: usize) {
    o.begin_item(next(seq), bits as u128).unwrap();
    o.fragment(next(seq), empty()).unwrap();
    fragments(|v| o.fragment(next(seq), v).unwrap(), data, bits);
    o.finish_item(next(seq)).unwrap();
}
fn result(o: &mut Owner, seq: &mut u64, id: u64, width: usize, last: u8) -> std::vec::Vec<u8> {
    if id <= 2 {
        o.finish(next(seq), width, last).unwrap();
    } else {
        o.finish(next(seq), 0, 0).unwrap();
        o.squeeze(next(seq), width, last, true).unwrap();
    }
    let mut output = std::vec![0xa5;width];
    o.export(next(seq), id, width, last, |v| {
        output.copy_from_slice(v);
        true
    })
    .unwrap();
    assert!(o.output.iter().all(|&v| v == 0));
    output
}
fn check_case(
    id: u64,
    custom: &[u8],
    custom_bits: usize,
    items: &[(&[u8], usize)],
    expected: &[u8],
    last: u8,
) {
    let mut o = Owner::new();
    let mut seq = 0;
    setup(&mut o, &mut seq, id, custom, custom_bits);
    for &(data, bits) in items {
        item(&mut o, &mut seq, data, bits);
    }
    assert_eq!(result(&mut o, &mut seq, id, expected.len(), last), expected);
}
fn cleared(o: &Owner) {
    assert_eq!(o.phase, Phase::Quarantined);
    assert!(matches!(o.state, State::Empty));
    assert_eq!(o.output, [0; 1024]);
    assert_eq!(o.remaining, [0; 16]);
}
#[test]
fn exact_items_reject_incomplete_overlong_interleaved_and_replayed_requests() {
    // Oversized snapshots must reject even when the declared item/customization
    // still has room; a length-overflow failure alone would mask this check.
    let mut o = Owner::new();
    let mut seq = 0;
    setup(&mut o, &mut seq, 1, &[], 0);
    o.begin_item(next(&mut seq), 9000).unwrap();
    assert_eq!(
        o.fragment(next(&mut seq), bytes(&[0; 1025]).unwrap()),
        Err(Error::Length)
    );
    cleared(&o);
    let mut o = Owner::new();
    o.begin(1, 1, 9000).unwrap();
    assert_eq!(o.custom(2, bytes(&[0; 1025]).unwrap()), Err(Error::Length));
    cleared(&o);
    for kind in 0..7 {
        let mut o = Owner::new();
        let mut seq = 0;
        setup(&mut o, &mut seq, 1, &[], 0);
        o.begin_item(next(&mut seq), 9).unwrap();
        let failure = match kind {
            0 => o.finish_item(next(&mut seq)),
            1 => o.fragment(next(&mut seq), bytes(&[0; 2]).unwrap()),
            2 => o.begin_item(next(&mut seq), 0),
            3 => o.finish(next(&mut seq), 32, 8),
            4 => o.fragment(seq, empty()),
            5 => o.fragment(next(&mut seq), bytes(&[0; 1025]).unwrap()),
            _ => {
                o.sequence = u64::MAX;
                o.fragment(0, empty())
            }
        };
        assert!(failure.is_err());
        cleared(&o);
        assert_eq!(o.cancel(100), Err(Error::State));
    }
    let mut o = Owner::new();
    o.begin(1, 1, 9).unwrap();
    o.custom(2, bytes(&[0]).unwrap()).unwrap();
    assert!(o.finish_custom(3).is_err());
    cleared(&o);
    let mut o = Owner::new();
    assert_eq!(o.begin(1, 5, 0), Err(Error::Identity));
    cleared(&o);
}
#[test]
fn tuple_boundaries_empty_items_and_xof_fragments_are_structural() {
    for id in 1..=4 {
        let digest = |items: &[&[u8]]| {
            let mut o = Owner::new();
            let mut seq = 0;
            setup(&mut o, &mut seq, id, &[], 0);
            for data in items {
                item(&mut o, &mut seq, data, data.len() * 8);
            }
            result(&mut o, &mut seq, id, 200, 7)
        };
        assert_ne!(digest(&[b"ab", b"c"]), digest(&[b"a", b"bc"]));
        assert_ne!(digest(&[]), digest(&[b""]));
        if id > 2 {
            let expected = digest(&[b"ab"]);
            let mut o = Owner::new();
            let mut seq = 0;
            setup(&mut o, &mut seq, id, &[], 0);
            item(&mut o, &mut seq, b"ab", 16);
            o.finish(next(&mut seq), 0, 0).unwrap();
            let mut combined = std::vec::Vec::new();
            for (n, last, end) in [(0, 0, false), (17, 8, false), (183, 7, true)] {
                o.squeeze(next(&mut seq), n, last, end).unwrap();
                o.export(next(&mut seq), id, n, last, |v| {
                    combined.extend_from_slice(v);
                    true
                })
                .unwrap();
            }
            assert_eq!(combined, expected);
        }
    }
}
#[test]
fn copy_failure_unwind_cancel_and_shapes_clear_retained_storage() {
    for mode in 0..6 {
        let mut o = Owner::new();
        let mut seq = 0;
        setup(&mut o, &mut seq, 1, &[], 0);
        o.finish(next(&mut seq), 32, 7).unwrap();
        assert!(o.output.iter().any(|&v| v != 0));
        match mode {
            0 => assert_eq!(
                o.export(next(&mut seq), 1, 32, 7, |_| false),
                Err(Error::Copy)
            ),
            1 => assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| o.export(
                    next(&mut seq),
                    1,
                    32,
                    7,
                    |_| panic!("copy fault")
                )))
                .is_err()
            ),
            2 => assert_eq!(
                o.export(next(&mut seq), 2, 32, 7, |_| true),
                Err(Error::Identity)
            ),
            3 => assert_eq!(
                o.export(next(&mut seq), 1, 32, 8, |_| true),
                Err(Error::Length)
            ),
            4 => {
                o.cancel(next(&mut seq)).unwrap();
                assert_eq!(o.phase, Phase::Empty);
                o.quarantine();
            }
            _ => o.quarantine(),
        }
        cleared(&o);
    }
    for (width, last) in [(1025, 8), (1, 0), (0, 1), (1, 9)] {
        let mut o = Owner::new();
        let mut seq = 0;
        setup(&mut o, &mut seq, 1, &[], 0);
        assert!(o.finish(next(&mut seq), width, last).is_err());
        cleared(&o);
    }
    let mut o = Owner::new();
    let mut seq = 0;
    setup(&mut o, &mut seq, 3, &[], 0);
    o.finish(next(&mut seq), 0, 0).unwrap();
    assert_eq!(o.squeeze(next(&mut seq), 1, 7, false), Err(Error::Bits));
    cleared(&o);
}
#[test]
fn retained_rehash_preserves_exact_bits_and_clears_previous_output() {
    for source in 1..=4 {
        for target in 1..=4 {
            for last in 1..=8 {
                let mut reference = Owner::new();
                let mut seq = 0;
                setup(&mut reference, &mut seq, source, &[], 0);
                item(&mut reference, &mut seq, b"abc", 24);
                let retained = result(&mut reference, &mut seq, source, 33, last);
                let mut expected = Owner::new();
                let mut seq = 0;
                setup(&mut expected, &mut seq, target, b"x", 8);
                item(&mut expected, &mut seq, &retained, 256 + usize::from(last));
                let digest = result(&mut expected, &mut seq, target, 40, 3);
                let mut o = Owner::new();
                let mut seq = 0;
                setup(&mut o, &mut seq, source, &[], 0);
                item(&mut o, &mut seq, b"abc", 24);
                if source <= 2 {
                    o.finish(next(&mut seq), 33, last).unwrap();
                } else {
                    o.finish(next(&mut seq), 0, 0).unwrap();
                    o.squeeze(next(&mut seq), 33, last, true).unwrap();
                }
                o.rehash(next(&mut seq), target, 8).unwrap();
                o.custom(next(&mut seq), bytes(b"x").unwrap()).unwrap();
                o.finish_custom(next(&mut seq)).unwrap();
                assert_eq!(o.output, [0; 1024]);
                assert_eq!(result(&mut o, &mut seq, target, 40, 3), digest);
            }
        }
    }
}
