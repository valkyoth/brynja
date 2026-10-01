use super::*;
use std::{
    boxed::Box,
    panic::{AssertUnwindSafe, catch_unwind},
    vec::Vec,
};
use tuple_accelerated::tuple_accelerated_wire::*;
fn header(seq: u64, id: u64, len: u64, last: u64, width: u64) -> [u8; 112] {
    let mut result = [0; 112];
    for (part, word) in result.chunks_exact_mut(8).zip([
        VERSION,
        seq,
        id,
        len,
        last,
        if len == 0 { 0 } else { 4096 },
        width,
        0,
        0,
        0,
        0,
        0,
        1,
        0,
    ]) {
        part.copy_from_slice(&word.to_le_bytes());
    }
    result
}
fn field(h: &mut [u8; 112], index: usize, value: u64) {
    h[index * 8..(index + 1) * 8].copy_from_slice(&value.to_le_bytes());
}
fn cleared(page: &Page) {
    for byte in &page.0 {
        // SAFETY: destruction writes every backing byte, including padding.
        assert_eq!(unsafe { byte.assume_init() }, 0);
    }
}
fn send(r: &mut Resident<'_>, seq: &mut u64, op: usize, mut h: [u8; 112], input: &[u8]) {
    *seq = seq.checked_add(1).unwrap();
    field(&mut h, 1, *seq);
    r.execute(op, &h, input, |_| panic!("unexpected output"))
        .unwrap();
}
fn empty() -> [u8; 112] {
    header(1, 0, 0, 0, 0)
}
fn fragments(r: &mut Resident<'_>, seq: &mut u64, op: usize, input: &[u8], bitlen: usize) {
    let mut start = 0;
    for size in [3, 8192, 7, 4096].into_iter().cycle() {
        if start == bitlen {
            break;
        }
        let n = size.min(bitlen - start);
        let mut data = std::vec![0; n.div_ceil(8)];
        for bit in 0..n {
            data[bit / 8] |= ((input[(start + bit) / 8] >> ((start + bit) % 8)) & 1) << (bit % 8);
        }
        send(
            r,
            seq,
            op,
            header(1, 0, data.len() as u64, ((n - 1) % 8 + 1) as u64, 0),
            &data,
        );
        start += n;
    }
}
fn setup(r: &mut Resident<'_>, seq: &mut u64, id: u64, custom: &[u8], bitlen: usize) {
    let mut h = header(1, id, 0, 0, 0);
    field(&mut h, 10, bitlen as u64);
    send(r, seq, BEGIN, h, &[]);
    fragments(r, seq, CUSTOM, custom, bitlen);
    send(r, seq, CUSTOM_END, empty(), &[]);
}
fn item(r: &mut Resident<'_>, seq: &mut u64, data: &[u8], bitlen: usize) {
    let mut h = empty();
    field(&mut h, 8, bitlen as u64);
    send(r, seq, ITEM_BEGIN, h, &[]);
    fragments(r, seq, FRAGMENT, data, bitlen);
    send(r, seq, ITEM_END, empty(), &[]);
}
fn finish(r: &mut Resident<'_>, seq: &mut u64, id: u64, width: usize, last: u8) {
    if id <= 2 {
        send(
            r,
            seq,
            FINISH,
            header(1, 0, 0, last as u64, width as u64),
            &[],
        );
    } else {
        send(r, seq, FINISH, empty(), &[]);
        let mut h = header(1, 0, 0, last as u64, width as u64);
        field(&mut h, 7, 1);
        send(r, seq, SQUEEZE, h, &[]);
    }
}
fn output(r: &mut Resident<'_>, seq: &mut u64, id: u64, width: usize, last: u8) -> Vec<u8> {
    *seq = seq.checked_add(1).unwrap();
    let mut result = Vec::new();
    r.execute(
        EXPORT,
        &header(*seq, id, 0, last as u64, width as u64),
        &[],
        |bytes| {
            result.extend_from_slice(bytes);
            true
        },
    )
    .unwrap();
    result
}
fn check_case(
    id: u64,
    custom: &[u8],
    custom_bits: usize,
    items: &[(&[u8], usize)],
    expected: &[u8],
    last: u8,
) {
    let mut page = Box::new(Page([MaybeUninit::new(0xa5); PAGE_BYTES]));
    let base = page.0.as_ptr().addr();
    let mut r = Resident::new(&mut page).unwrap();
    assert_eq!(r.authority.as_ptr().addr(), base);
    assert_eq!(r.owner.as_ptr().addr(), base + OWNER_OFFSET);
    let mut seq = 0;
    setup(&mut r, &mut seq, id, custom, custom_bits);
    for &(data, bits) in items {
        item(&mut r, &mut seq, data, bits);
    }
    finish(&mut r, &mut seq, id, expected.len(), last);
    assert_eq!(output(&mut r, &mut seq, id, expected.len(), last), expected);
    drop(r);
    cleared(&page);
}
fn retained(r: &mut Resident<'_>) -> u64 {
    let mut seq = 0;
    setup(r, &mut seq, 1, &[], 0);
    item(r, &mut seq, b"abc", 24);
    finish(r, &mut seq, 1, 32, 8);
    seq
}
fn revoked(r: &mut Resident<'_>, seq: u64) {
    // SAFETY: placed shared authority access; no competing mutation.
    assert!(unsafe { r.authority.as_ref() }.session().is_err());
    assert!(
        r.execute(CANCEL, &header(seq + 1, 0, 0, 0, 0), &[], |_| panic!(
            "revoked copy"
        ))
        .is_err()
    );
}
#[test]
fn malformed_metadata_is_rejected_before_payload() {
    for (op, index, value) in [
        (BEGIN, 0, 9),
        (BEGIN, 1, 0),
        (BEGIN, 12, 0),
        (BEGIN, 12, 2),
        (BEGIN, 13, 1),
        (BEGIN, 2, 5),
        (FRAGMENT, 2, 1),
        (BEGIN, 3, 1),
        (FRAGMENT, 3, 1025),
        (FRAGMENT, 5, 0),
        (FRAGMENT, 5, u64::MAX),
        (BEGIN, 5, 4096),
        (FRAGMENT, 4, 0),
        (FINISH, 4, 9),
        (BEGIN, 4, 1),
        (BEGIN, 6, 1),
        (FINISH, 6, 1025),
        (SQUEEZE, 4, 0),
        (SQUEEZE, 7, 2),
        (BEGIN, 7, 1),
        (FRAGMENT, 8, 1),
        (FRAGMENT, 9, 1),
        (FRAGMENT, 10, 1),
        (FRAGMENT, 11, 1),
    ] {
        let mut h = match op {
            FRAGMENT => header(1, 0, 1, 8, 0),
            FINISH | SQUEEZE => header(1, 0, 0, 8, 32),
            _ => header(1, 1, 0, 0, 0),
        };
        assert!(Request::decode(op, &h).is_ok());
        field(&mut h, index, value);
        if op == BEGIN && index == 3 {
            field(&mut h, 5, 4096);
        }
        assert!(Request::decode(op, &h).is_err(), "op {op} field {index}");
    }
    for op in [0, 3, 59, 71, usize::MAX] {
        assert!(Request::decode(op, &empty()).is_err());
    }
    for op in [CUSTOM, FRAGMENT] {
        assert!(Request::decode(op, &header(1, 0, 0, 1, 0)).is_err());
        assert!(Request::decode(op, &header(1, 0, 1, 0, 0)).is_err());
    }
    for op in [FINISH, SQUEEZE, EXPORT] {
        assert!(Request::decode(op, &header(1, u64::from(op == EXPORT), 0, 0, 1)).is_err());
        assert!(Request::decode(op, &header(1, u64::from(op == EXPORT), 0, 1, 0)).is_err());
    }
    assert!(Request::decode(SQUEEZE, &header(1, 0, 0, 7, 1)).is_err());
}
#[test]
fn decode_payload_copy_and_unwind_failures_revoke() {
    // Both the copied bits and customization budget are valid: only the
    // declared-vs-copied byte count can reject this snapshot.
    let mut page = Box::new(Page::empty());
    let mut r = Resident::new(&mut page).unwrap();
    let mut h = header(1, 1, 0, 0, 0);
    field(&mut h, 10, 32);
    r.execute(BEGIN, &h, &[], |_| false).unwrap();
    assert_eq!(
        r.execute(CUSTOM, &header(2, 0, 3, 8, 0), b"ab", |_| false),
        Err(Error::Length)
    );
    revoked(&mut r, 1);
    drop(r);
    cleared(&page);
    for failure in 0..7 {
        let mut page = Box::new(Page::empty());
        let mut r = Resident::new(&mut page).unwrap();
        let seq = retained(&mut r);
        let mut h = header(seq + 1, 1, 0, 8, 32);
        if failure == 0 {
            field(&mut h, 0, 9);
        }
        if failure == 1 {
            field(&mut h, 12, 0);
        }
        let result = catch_unwind(AssertUnwindSafe(|| {
            if failure == 5 {
                r.quarantine();
            }
            r.execute(EXPORT, &h, if failure == 2 { b"x" } else { b"" }, |_| {
                if failure == 4 {
                    panic!("copy fault");
                }
                failure == 6
            })
        }));
        if failure == 6 {
            result.unwrap().unwrap();
        } else {
            if failure == 4 {
                assert!(result.is_err());
            } else {
                assert!(result.unwrap().is_err());
            }
            revoked(&mut r, seq + 1);
        }
        drop(r);
        cleared(&page);
    }
    // A malformed copied bit string fails before Owner::custom; the wire guard
    // itself must revoke. Subsequent replay must not mask missing revocation.
    for input in [&[0x80][..], &[][..]] {
        let mut page = Box::new(Page::empty());
        let mut r = Resident::new(&mut page).unwrap();
        let mut h = header(1, 1, 0, 0, 0);
        field(&mut h, 10, 1);
        r.execute(BEGIN, &h, &[], |_| false).unwrap();
        assert!(
            r.execute(CUSTOM, &header(2, 0, 1, 1, 0), input, |_| false)
                .is_err()
        );
        revoked(&mut r, 1);
        drop(r);
        cleared(&page);
    }
}
#[test]
fn every_phase_drop_cancel_and_retained_composition() {
    for cancel in [false, true] {
        for phase in 0..9 {
            let mut page = Box::new(Page([MaybeUninit::new(0xa5); PAGE_BYTES]));
            let mut r = Resident::new(&mut page).unwrap();
            let mut seq = 0;
            send(&mut r, &mut seq, BEGIN, header(1, 3, 0, 0, 0), &[]);
            if phase >= 1 {
                send(&mut r, &mut seq, CUSTOM_END, empty(), &[]);
            }
            if phase >= 2 {
                let mut h = empty();
                field(&mut h, 8, 1);
                send(&mut r, &mut seq, ITEM_BEGIN, h, &[]);
                send(&mut r, &mut seq, FRAGMENT, header(1, 0, 1, 1, 0), &[1]);
            }
            if phase >= 3 {
                send(&mut r, &mut seq, ITEM_END, empty(), &[]);
            }
            if phase >= 4 {
                send(&mut r, &mut seq, FINISH, empty(), &[]);
            }
            if phase >= 5 {
                let mut h = header(1, 0, 0, 8, 32);
                field(&mut h, 7, u64::from(phase == 6));
                send(&mut r, &mut seq, SQUEEZE, h, &[]);
            }
            if phase >= 7 {
                send(&mut r, &mut seq, REHASH, header(1, 2, 0, 0, 0), &[]);
            }
            if phase >= 8 {
                send(&mut r, &mut seq, CUSTOM_END, empty(), &[]);
            }
            if cancel {
                send(&mut r, &mut seq, CANCEL, empty(), &[]);
                setup(&mut r, &mut seq, 1, &[], 0);
                r.quarantine();
                revoked(&mut r, seq);
            }
            drop(r);
            cleared(&page);
        }
    }
}
#[test]
fn all_retained_compositions_and_incremental_xof() {
    for source in 1..=4 {
        for target in 1..=4 {
            let mut page = Box::new(Page::empty());
            let mut r = Resident::new(&mut page).unwrap();
            let mut seq = 0;
            setup(&mut r, &mut seq, source, &[], 0);
            item(&mut r, &mut seq, b"abc", 24);
            finish(&mut r, &mut seq, source, 33, 3);
            let value = output(&mut r, &mut seq, source, 33, 3);
            setup(&mut r, &mut seq, target, b"x", 8);
            item(&mut r, &mut seq, &value, 259);
            finish(&mut r, &mut seq, target, 40, 7);
            let expected = output(&mut r, &mut seq, target, 40, 7);
            setup(&mut r, &mut seq, source, &[], 0);
            item(&mut r, &mut seq, b"abc", 24);
            finish(&mut r, &mut seq, source, 33, 3);
            let mut h = header(1, target, 0, 0, 0);
            field(&mut h, 10, 8);
            send(&mut r, &mut seq, REHASH, h, &[]);
            fragments(&mut r, &mut seq, CUSTOM, b"x", 8);
            send(&mut r, &mut seq, CUSTOM_END, empty(), &[]);
            finish(&mut r, &mut seq, target, 40, 7);
            assert_eq!(output(&mut r, &mut seq, target, 40, 7), expected);
            if target > 2 {
                setup(&mut r, &mut seq, target, b"x", 8);
                item(&mut r, &mut seq, &value, 259);
                send(&mut r, &mut seq, FINISH, empty(), &[]);
                let mut combined = Vec::new();
                for (width, last, end) in [(0, 0, false), (17, 8, false), (23, 7, true)] {
                    let mut h = header(1, 0, 0, last as u64, width as u64);
                    field(&mut h, 7, u64::from(end));
                    send(&mut r, &mut seq, SQUEEZE, h, &[]);
                    combined.extend(output(&mut r, &mut seq, target, width, last));
                }
                assert_eq!(combined, expected);
            }
            drop(r);
            cleared(&page);
        }
    }
}
