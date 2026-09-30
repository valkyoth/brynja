use super::parallel_stream_wire::*;
use super::*;
fn header(words: [u64; 14]) -> [u8; HEADER_BYTES] {
    let mut out = [0; HEADER_BYTES];
    for (word, chunk) in words.into_iter().zip(out.chunks_exact_mut(8)) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    out
}
#[test]
fn metadata_bounds_are_canonical_before_payload_copy() {
    let begin = [12, 1, 1, 8, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert!(Header::decode(BEGIN, &header(begin)).is_ok());
    for (field, value) in [
        (0, 11),
        (1, 0),
        (2, 0),
        (2, 5),
        (3, 0),
        (7, 1),
        (8, 1),
        (9, 1),
        (10, 1),
        (11, 1),
        (12, 1),
        (13, 1),
    ] {
        let mut changed = begin;
        changed[field] = value;
        assert!(
            Header::decode(BEGIN, &header(changed)).is_err(),
            "{field} {value}"
        );
    }
    for op in [99, 108, usize::MAX] {
        assert!(Header::decode(op, &header(begin)).is_err());
    }
    for op in [CUSTOM, UPDATE, FINISH] {
        let request = [12, 2, 0, 0, 0, 0, 0, 1, 8, 0, 0, 0, 0x1000, 0];
        assert!(Header::decode(op, &header(request)).is_ok());
        for (field, value) in [
            (2, 1),
            (3, 1),
            (4, 1),
            (5, 1),
            (6, 1),
            (7, 1025),
            (8, 9),
            (8, 0),
            (11, 1),
            (12, 0),
            (12, u64::MAX),
            (13, 1),
        ] {
            let mut changed = request;
            changed[field] = value;
            assert!(
                Header::decode(op, &header(changed)).is_err(),
                "{op} {field} {value}"
            );
        }
    }
    assert!(
        Header::decode(
            UPDATE,
            &header([12, 2, 0, 0, 0, 0, 0, 1, 7, 0, 0, 0, 0x1000, 0])
        )
        .is_err()
    );
    for (width, last, terminal) in [
        (1025, 8, 1),
        (0, 1, 1),
        (1, 0, 1),
        (1, 9, 1),
        (1, 7, 0),
        (1, 8, 2),
    ] {
        assert!(
            Header::decode(
                SQUEEZE,
                &header([12, 3, 0, 0, 0, 0, 0, 0, 0, width, last, terminal, 0, 0])
            )
            .is_err()
        );
    }
}
#[test]
fn copied_payload_failure_clears_an_active_owner() {
    for malformed in [false, true] {
        let mut o = Owner::new();
        o.begin(1, 1, 8, 0, 100).unwrap();
        o.finish_custom(2).unwrap();
        let h = Header::decode(
            FINISH,
            &header([12, 3, 0, 0, 0, 0, 0, 1, 1, 32, 8, 0, 0x1000, 0]),
        )
        .unwrap();
        let input: &[u8] = if malformed { &[0x80] } else { &[] };
        assert!(h.execute(&mut o, input, |_| panic!("no export")).is_err());
        assert_eq!(o.phase, Phase::Quarantined);
        assert!(o.input.cleared());
        assert_eq!(o.output, [0; 1024]);
    }
}
#[test]
fn complete_wire_request_executes_fixed_and_incremental_xof() {
    for id in 1..=4 {
        let mut reference = Owner::new();
        reference.begin(1, id, 8, 0, 10).unwrap();
        reference.finish_custom(2).unwrap();
        reference.update(3, b"abc").unwrap();
        reference
            .finish(
                4,
                empty().unwrap(),
                if id <= 2 { 32 } else { 0 },
                if id <= 2 { 8 } else { 0 },
            )
            .unwrap();
        if id > 2 {
            reference.squeeze(5, 32, 8, false).unwrap();
        }
        let expected = &reference.output[..32];
        let mut o = Owner::new();
        let mut seq = 0;
        let mut call = |op, mut words: [u64; 14], input: &[u8]| {
            seq += 1;
            words[0] = 12;
            words[1] = seq;
            Header::decode(op, &header(words))
                .unwrap()
                .execute(&mut o, input, |x| {
                    assert_eq!(x, expected);
                    true
                })
                .unwrap();
        };
        let mut h = [0; 14];
        h[2] = id;
        h[3] = 8;
        h[4] = 10;
        call(BEGIN, h, &[]);
        call(SETUP, [0; 14], &[]);
        let mut h = [0; 14];
        h[7] = 3;
        h[8] = 8;
        h[12] = 0x1000;
        call(UPDATE, h, b"abc");
        let mut h = [0; 14];
        if id <= 2 {
            h[9] = 32;
            h[10] = 8;
        }
        call(FINISH, h, &[]);
        if id > 2 {
            let mut h = [0; 14];
            h[9] = 32;
            h[10] = 8;
            call(SQUEEZE, h, &[]);
        }
        let mut h = [0; 14];
        h[2] = id;
        h[9] = 32;
        h[10] = 8;
        call(EXPORT, h, &[]);
        if id > 2 {
            call(CANCEL, [0; 14], &[]);
        }
        assert_eq!(o.phase, Phase::Empty);
        assert!(o.input.cleared());
    }
}
