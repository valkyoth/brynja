use super::sha2_batch_wire::*;
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};
fn encode(words: [u64; 16]) -> [u8; 128] {
    let mut bytes = [0; 128];
    for (word, chunk) in words.iter().zip(bytes.chunks_exact_mut(8)) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    bytes
}
fn request(op: usize, n: u64, slot: u64, input: &[u8], last: u8) -> [u8; 128] {
    let mut words = [0; 16];
    words[..8].copy_from_slice(&[
        VERSION,
        n,
        slot,
        input.len() as u64,
        u64::from(last),
        if input.is_empty() {
            0
        } else {
            input.as_ptr() as u64
        },
        0,
        0,
    ]);
    if matches!(op, BEGIN | EXPORT) {
        words[8..].copy_from_slice(&[1, 2, 3, 4, 5, 6, 0x1001, 0x11ff]);
    }
    if op == BEGIN {
        words[6] = u64::MAX;
    }
    encode(words)
}
fn execute(o: &mut Owner, op: usize, n: u64, slot: u64, input: &[u8], last: u8) {
    Header::decode(op, &request(op, n, slot, input, last))
        .unwrap()
        .execute(o, input, |_| panic!("unexpected export"))
        .unwrap();
}
#[test]
fn complete_wire_batch_binds_all_eight_named_and_general_slots() {
    let mut o = Owner::new();
    execute(&mut o, BEGIN, 1, 0, &[], 0);
    let mut n = 1;
    for slot in 0..8 {
        n += 1;
        execute(&mut o, START, n, slot, &[], 0);
        n += 1;
        execute(&mut o, UPDATE, n, slot, b"ab", 8);
        n += 1;
        execute(&mut o, FINISH, n, slot, b"c", 8);
    }
    n += 1;
    execute(&mut o, SEAL, n, 0, &[], 0);
    let expected = o.output;
    assert!(expected.iter().any(|b| *b != 0));
    n += 1;
    Header::decode(EXPORT, &request(EXPORT, n, 0, &[], 0))
        .unwrap()
        .execute(&mut o, &[], |value| {
            assert_eq!(*value, expected);
            true
        })
        .unwrap();
    assert_eq!(o.output, [0; 512]);
    assert_eq!(o.phase, Phase::Empty);
}
#[test]
fn metadata_rejects_noncanonical_words_and_ranges_before_copy() {
    for op in BEGIN..=CANCEL {
        let payload = matches!(op, UPDATE | FINISH);
        let input: &[u8] = if payload { b"abc" } else { &[] };
        let header = request(op, 1, 0, input, if payload { 8 } else { 0 });
        let decoded = Header::decode(op, &header).unwrap();
        assert_eq!(decoded.length(), input.len());
        assert_eq!(
            decoded.source(),
            if payload { input.as_ptr() as usize } else { 0 }
        );
        for (word, value) in [(0, 9), (1, 0), (7, 1), (3, 1025), (4, 9), (2, 8)] {
            let mut changed = header;
            changed[word * 8..word * 8 + 8].copy_from_slice(&u64::to_le_bytes(value));
            assert!(
                Header::decode(op, &changed).is_err(),
                "op={op}; word={word}"
            );
        }
        if op != BEGIN {
            let mut changed = header;
            changed[48..56].copy_from_slice(&1_u64.to_le_bytes());
            assert!(Header::decode(op, &changed).is_err());
        }
        let mut changed = header;
        changed[64..72].copy_from_slice(&7_u64.to_le_bytes());
        assert!(Header::decode(op, &changed).is_err());
        if !matches!(op, BEGIN | EXPORT) {
            let mut changed = header;
            changed[64..72].copy_from_slice(&2_u64.to_le_bytes());
            assert!(Header::decode(op, &changed).is_err());
        } else {
            let mut changed = header;
            changed[64..].fill(0);
            assert!(Header::decode(op, &changed).is_err());
        }
    }
    for op in [0, 79, 87, usize::MAX] {
        assert!(Header::decode(op, &request(BEGIN, 1, 0, &[], 0)).is_err());
    }
    let mut header = request(UPDATE, 1, 0, b"abc", 8);
    header[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(Header::decode(UPDATE, &header).is_err());
    header[40..48].fill(0);
    assert!(Header::decode(UPDATE, &header).is_err());
    let mut header = request(UPDATE, 1, 0, b"abc", 8);
    header[32..40].copy_from_slice(&3_u64.to_le_bytes());
    assert!(Header::decode(UPDATE, &header).is_err());
}
#[test]
fn copied_length_and_bits_fail_closed_and_copy_unwind_erases() {
    let mut o = Owner::new();
    execute(&mut o, BEGIN, 1, 0, &[], 0);
    execute(&mut o, START, 2, 0, &[], 0);
    let header = Header::decode(UPDATE, &request(UPDATE, 3, 0, b"abc", 8)).unwrap();
    assert!(header.execute(&mut o, b"ab", |_| panic!()).is_err());
    assert_eq!(o.phase, Phase::Quarantined);
    assert_eq!(o.output, [0; 512]);
    let mut o = Owner::new();
    execute(&mut o, BEGIN, 1, 0, &[], 0);
    execute(&mut o, START, 2, 0, &[], 0);
    let header = Header::decode(FINISH, &request(FINISH, 3, 0, &[1], 3)).unwrap();
    assert!(header.execute(&mut o, &[1], |_| panic!()).is_err());
    assert_eq!(o.phase, Phase::Quarantined);
    let mut o = Owner::new();
    execute(&mut o, BEGIN, 1, 0, &[], 0);
    let mut n = 1;
    for slot in 0..8 {
        n += 1;
        execute(&mut o, START, n, slot, &[], 0);
        n += 1;
        execute(&mut o, FINISH, n, slot, b"abc", 8);
    }
    n += 1;
    execute(&mut o, SEAL, n, 0, &[], 0);
    n += 1;
    let header = Header::decode(EXPORT, &request(EXPORT, n, 0, &[], 0)).unwrap();
    assert!(
        catch_unwind(AssertUnwindSafe(|| header.execute(
            &mut o,
            &[],
            |_| panic!("copy failure")
        )))
        .is_err()
    );
    assert_eq!(o.output, [0; 512]);
    assert_eq!(o.phase, Phase::Quarantined);
}
