use super::sha3_batch_wire::*;
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn shapes() -> [Slot; 8] {
    let widths = [28, 32, 48, 64, 169, 137, 33, 1];
    core::array::from_fn(|i| Slot {
        identity: (i + 1) as u64,
        width: widths[i],
        last: if i >= 4 { 3 } else { 8 },
    })
}
fn request(op: usize, n: u64, slot: usize, input: &[u8], last: u8) -> [u8; HEADER_BYTES] {
    let mut words = [0_u64; 36];
    words[..8].copy_from_slice(&[
        VERSION,
        n,
        slot as u64,
        input.len() as u64,
        last as u64,
        if input.is_empty() {
            0
        } else {
            input.as_ptr() as u64
        },
        if op == BEGIN { u64::MAX } else { 0 },
        0,
    ]);
    if matches!(op, BEGIN | EXPORT) {
        for (triple, s) in words[12..].chunks_exact_mut(3).zip(shapes()) {
            triple.copy_from_slice(&[s.identity, s.width as u64, s.last as u64]);
        }
    }
    if op == START && slot >= 6 {
        words[8] = 3;
        words[10] = 5;
    }
    let mut bytes = [0; HEADER_BYTES];
    for (chunk, word) in bytes.chunks_exact_mut(8).zip(words) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    bytes
}
fn execute(o: &mut Owner, op: usize, n: &mut u64, slot: usize, input: &[u8], last: u8) {
    *n += 1;
    Header::decode(op, &request(op, *n, slot, input, last))
        .unwrap()
        .execute(o, input, |_| panic!("unexpected export"))
        .unwrap();
}
fn retained() -> (Owner, u64) {
    let mut o = Owner::new();
    let mut n = 0;
    execute(&mut o, BEGIN, &mut n, 0, &[], 0);
    for slot in 0..8 {
        execute(&mut o, START, &mut n, slot, &[], 0);
        if slot >= 6 {
            execute(&mut o, NAME, &mut n, slot, &[5], 3);
            execute(&mut o, CUSTOM, &mut n, slot, &[17], 5);
        }
        execute(&mut o, SETUP, &mut n, slot, &[], 0);
        execute(&mut o, UPDATE, &mut n, slot, b"ab", 8);
        execute(&mut o, FINISH, &mut n, slot, b"c", 8);
    }
    execute(&mut o, SEAL, &mut n, 0, &[], 0);
    (o, n)
}
fn failed(o: &Owner) {
    assert_eq!(o.phase, Phase::Quarantined);
    assert_eq!(o.output, [0; 1024]);
    assert!(matches!(o.state, State::Empty));
}
#[test]
fn complete_wire_batch_binds_setup_order_and_output_shapes() {
    let (mut o, n) = retained();
    let mut expected = [0_u8; 1024];
    let mut offset = 0;
    for s in shapes() {
        let empty = Fips202BitString::new(&[], 0).unwrap();
        let mut reference = State::new(
            Algorithm::decode(s.identity).unwrap(),
            if s.identity >= 7 {
                Fips202BitString::new(&[5], 3).unwrap()
            } else {
                empty
            },
            if s.identity >= 7 {
                Fips202BitString::new(&[17], 5).unwrap()
            } else {
                empty
            },
        )
        .unwrap();
        let bits = Fips202BitString::new(b"abc", 8).unwrap();
        let out = &mut expected[offset..offset + s.width];
        if s.identity <= 4 {
            reference.finish_fixed(bits, out).unwrap();
        } else {
            reference.finish_xof(bits).unwrap();
            reference.squeeze(out, s.last, true).unwrap();
        }
        offset += s.width;
    }
    Header::decode(EXPORT, &request(EXPORT, n + 1, 0, &[], 0))
        .unwrap()
        .execute(&mut o, &[], |out| {
            assert_eq!(*out, expected);
            true
        })
        .unwrap();
    assert_eq!(o.phase, Phase::Empty);
    assert_eq!(o.output, [0; 1024]);
}
#[test]
fn header_rejects_noncanonical_metadata_before_payload_copy() {
    for op in BEGIN..=CANCEL {
        let payload = matches!(op, NAME | CUSTOM | UPDATE | FINISH);
        let input: &[u8] = if payload { b"abc" } else { &[] };
        let header = request(op, 1, 0, input, if payload { 8 } else { 0 });
        let parsed = Header::decode(op, &header).unwrap();
        assert_eq!(parsed.length(), input.len());
        assert_eq!(
            parsed.source(),
            if payload { input.as_ptr() as usize } else { 0 }
        );
        for (word, value) in [(0, 10_u64), (1, 0), (2, 8), (3, 1025), (4, 9), (7, 1)] {
            let mut changed = header;
            changed[word * 8..word * 8 + 8].copy_from_slice(&value.to_le_bytes());
            assert!(Header::decode(op, &changed).is_err(), "op={op} word={word}");
        }
        if op != BEGIN {
            let mut changed = header;
            changed[48..56].copy_from_slice(&1_u64.to_le_bytes());
            assert!(Header::decode(op, &changed).is_err());
        }
        for word in 8..12 {
            let mut changed = header;
            changed[word * 8..word * 8 + 8].copy_from_slice(&1_u64.to_le_bytes());
            assert_eq!(Header::decode(op, &changed).is_ok(), op == START);
        }
        if matches!(op, BEGIN | EXPORT) {
            let mut changed = header;
            changed[96..].fill(0);
            assert!(Header::decode(op, &changed).is_err());
            for word in [12, 13, 14] {
                let mut changed = header;
                changed[word * 8..word * 8 + 8].copy_from_slice(&u64::MAX.to_le_bytes());
                assert!(Header::decode(op, &changed).is_err());
            }
            let mut changed = header;
            changed[96..104].copy_from_slice(&5_u64.to_le_bytes());
            changed[104..112].copy_from_slice(&1024_u64.to_le_bytes());
            assert!(Header::decode(op, &changed).is_err());
        } else {
            let mut changed = header;
            changed[96..104].copy_from_slice(&5_u64.to_le_bytes());
            assert!(Header::decode(op, &changed).is_err());
        }
    }
    for op in [0, 89, 100, usize::MAX] {
        assert!(Header::decode(op, &request(BEGIN, 1, 0, &[], 0)).is_err());
    }
    for source in [0, u64::MAX] {
        let mut header = request(UPDATE, 1, 0, b"abc", 8);
        header[40..48].copy_from_slice(&source.to_le_bytes());
        assert!(Header::decode(UPDATE, &header).is_err());
    }
    let mut header = request(UPDATE, 1, 0, b"abc", 8);
    header[32..40].copy_from_slice(&3_u64.to_le_bytes());
    assert!(Header::decode(UPDATE, &header).is_err());
}
#[test]
fn wire_failure_with_retained_results_and_unwind_clear_all() {
    let (mut o, n) = retained();
    // Exact copied payload length is checked even for zero-payload operations.
    assert!(
        Header::decode(EXPORT, &request(EXPORT, n + 1, 0, &[], 0))
            .unwrap()
            .execute(&mut o, &[1], |_| panic!("invalid payload exported"))
            .is_err()
    );
    failed(&o);
    let (mut o, n) = retained();
    let header = Header::decode(EXPORT, &request(EXPORT, n + 1, 0, &[], 0)).unwrap();
    assert!(
        catch_unwind(AssertUnwindSafe(|| header.execute(
            &mut o,
            &[],
            |_| panic!("copy seam")
        )))
        .is_err()
    );
    failed(&o);
    let mut o = Owner::new();
    let mut n = 0;
    execute(&mut o, BEGIN, &mut n, 0, &[], 0);
    execute(&mut o, START, &mut n, 0, &[], 0);
    execute(&mut o, SETUP, &mut n, 0, &[], 0);
    execute(&mut o, FINISH, &mut n, 0, b"retained", 8);
    execute(&mut o, START, &mut n, 1, &[], 0);
    execute(&mut o, SETUP, &mut n, 1, &[], 0);
    execute(&mut o, UPDATE, &mut n, 1, b"secret", 8);
    assert!(
        Header::decode(FINISH, &request(FINISH, n + 1, 1, &[128], 1))
            .unwrap()
            .execute(&mut o, &[128], |_| panic!())
            .is_err()
    );
    failed(&o);
}
