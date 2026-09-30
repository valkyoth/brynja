use super::*;
fn check_rehash(source: u64, target: u64, last: u8, block: u64, expected: &[u8]) {
    let mut o = Owner::new();
    o.begin(1, source, 8, 0, 3).unwrap();
    o.finish_custom(2).unwrap();
    o.update(3, b"abc").unwrap();
    o.finish(
        4,
        empty().unwrap(),
        if source <= 2 { 33 } else { 0 },
        if source <= 2 { last } else { 0 },
    )
    .unwrap();
    let mut seq = 4;
    if source > 2 {
        seq += 1;
        o.squeeze(seq, 33, last, true).unwrap();
    }
    seq += 1;
    o.rehash(
        seq,
        target,
        block,
        5,
        34,
        if target <= 2 { (33, 3) } else { (0, 0) },
    )
    .unwrap();
    seq += 1;
    o.custom(seq, Bits::new(&[19], 5).unwrap()).unwrap();
    seq += 1;
    o.finish_custom(seq).unwrap();
    if target > 2 {
        assert_eq!(o.output, [0; 1024]);
        seq += 1;
        o.squeeze(seq, 33, 3, true).unwrap();
    }
    seq += 1;
    o.export(seq, target, 33, 3, |bytes| {
        assert_eq!(bytes, expected);
        true
    })
    .unwrap();
    assert_eq!(o.phase, Phase::Empty);
    assert!(o.input.cleared());
    assert_eq!((o.next_width, o.next_last), (0, 0));
    assert_eq!(o.output, [0; 1024]);
}
#[test]
fn retained_setup_rejection_and_cancel_clear_previous_output() {
    // Synthetic retained bytes isolate lifecycle checks from expensive hashing
    // under Miri. The generated oracle separately exercises real source digests.
    for fail in 0..4 {
        let mut o = Owner::new();
        o.phase = Phase::Retained;
        o.identity = 1;
        o.width = 33;
        o.last = 3;
        o.output[..33].fill(1);
        match fail {
            0 => assert!(o.rehash(1, 1, 8, 0, 32, (32, 8)).is_err()),
            1 => {
                o.rehash(1, 1, 8, 1, 34, (32, 8)).unwrap();
                assert!(o.finish_custom(2).is_err());
            }
            2 => {
                o.rehash(1, 1, 8, 0, 33, (32, 8)).unwrap();
                o.cancel(2).unwrap();
            }
            _ => {
                o.rehash(1, 1, 8, 0, 33, (32, 8)).unwrap();
                assert!(o.update(2, b"x").is_err());
            }
        }
        assert_eq!(
            o.phase,
            if fail == 2 {
                Phase::Empty
            } else {
                Phase::Quarantined
            }
        );
        assert_eq!(o.output, [0; 1024]);
        assert_eq!((o.next_width, o.next_last), (0, 0));
        assert!(o.input.cleared());
    }
}
