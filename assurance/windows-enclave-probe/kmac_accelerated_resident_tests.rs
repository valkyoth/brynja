use super::*;
use kmac_accelerated::kmac_accelerated_wire::*;
use std::{
    boxed::Box,
    panic::{AssertUnwindSafe, catch_unwind},
    vec::Vec,
};

#[path = "kmac_accelerated_resident_composition_tests.rs"]
mod kmac_accelerated_resident_composition_tests;

fn header(seq: u64, id: u64, len: u64, last: u64, width: u64) -> [u8; 112] {
    let words = [
        15,
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
    ];
    let mut result = [0; 112];
    for (slot, word) in result.chunks_exact_mut(8).zip(words) {
        slot.copy_from_slice(&word.to_le_bytes());
    }
    result
}
fn field(h: &mut [u8; 112], index: usize, value: u64) {
    h[index * 8..(index + 1) * 8].copy_from_slice(&value.to_le_bytes());
}
fn cleared(page: &Page) {
    for byte in &page.0 {
        // SAFETY: destruction initializes every backing byte by clearing it.
        assert_eq!(unsafe { byte.assume_init() }, 0);
    }
}
fn send(
    r: &mut Resident<'_>,
    seq: &mut u64,
    op: usize,
    id: u64,
    data: &[u8],
    last: u8,
    width: u64,
) {
    *seq += 1;
    r.execute(
        op,
        &header(*seq, id, data.len() as u64, u64::from(last), width),
        data,
        |_| panic!("unexpected public copy"),
    )
    .unwrap();
}
fn feed(r: &mut Resident<'_>, seq: &mut u64, op: usize, data: &[u8], last: u8) {
    let complete = data.len() - usize::from(!data.is_empty() && last != 8);
    for chunk in data[..complete].chunks(37) {
        send(r, seq, op, 0, chunk, 8, 0);
    }
    if (1..8).contains(&last) {
        for bit in 0..last {
            send(r, seq, op, 0, &[(data[complete] >> bit) & 1], 1, 0);
        }
    }
}
fn setup(r: &mut Resident<'_>, seq: &mut u64, id: u64, key: &[u8], kl: u8, custom: &[u8], cl: u8) {
    *seq += 1;
    let mut h = header(*seq, id, 0, 0, 0);
    field(&mut h, 8, ((key.len() - 1) * 8 + usize::from(kl)) as u64);
    field(
        &mut h,
        10,
        if custom.is_empty() {
            0
        } else {
            ((custom.len() - 1) * 8 + usize::from(cl)) as u64
        },
    );
    r.execute(BEGIN, &h, &[], |_| false).unwrap();
    feed(r, seq, CUSTOM, custom, cl);
    send(r, seq, CUSTOM_END, 0, &[], 0, 0);
    feed(r, seq, KEY, key, kl);
    send(r, seq, SETUP_END, 0, &[], 0, 0);
}
fn finish(
    r: &mut Resident<'_>,
    seq: &mut u64,
    id: u64,
    message: &[u8],
    ml: u8,
    width: usize,
    last: u8,
) {
    let complete = message.len() - usize::from(!message.is_empty() && ml != 8);
    for chunk in message[..complete].chunks(37) {
        send(r, seq, UPDATE, 0, chunk, 8, 0);
    }
    let bits = if width == 0 {
        0
    } else {
        (width - 1) * 8 + usize::from(last)
    };
    send(
        r,
        seq,
        FINISH,
        0,
        &message[complete..],
        if complete == message.len() { 0 } else { ml },
        if id <= 2 { bits as u64 } else { 0 },
    );
}
fn output(r: &mut Resident<'_>, seq: &mut u64, id: u64, width: usize, last: u8) -> Vec<u8> {
    let mut result = Vec::new();
    if id > 2 {
        *seq += 1;
        let mut h = header(*seq, 0, 0, u64::from(last), width as u64);
        field(&mut h, 7, 1);
        r.execute(SQUEEZE, &h, &[], |_| false).unwrap();
    }
    *seq += 1;
    r.execute(
        EXPORT,
        &header(*seq, id, 0, u64::from(last), width as u64),
        &[],
        |bytes| {
            result.extend_from_slice(bytes);
            true
        },
    )
    .unwrap();
    result
}
// The build script appends independently generated Python bit-oracle cases.
fn check_case(
    id: u64,
    key: &[u8],
    kl: u8,
    custom: &[u8],
    cl: u8,
    message: &[u8],
    ml: u8,
    expected: &[u8],
    last: u8,
) {
    let mut page = Box::new(Page([MaybeUninit::new(0xa5); PAGE_BYTES]));
    let base = page.0.as_ptr().addr();
    let mut resident = Resident::new(&mut page).unwrap();
    assert_eq!(resident.authority.as_ptr().addr(), base);
    assert_eq!(resident.owner.as_ptr().addr(), base + OWNER_OFFSET);
    let mut seq = 0;
    setup(&mut resident, &mut seq, id, key, kl, custom, cl);
    finish(
        &mut resident,
        &mut seq,
        id,
        message,
        ml,
        expected.len(),
        last,
    );
    assert_eq!(
        output(&mut resident, &mut seq, id, expected.len(), last),
        expected
    );
    drop(resident);
    cleared(&page);
}
fn retained(r: &mut Resident<'_>) -> u64 {
    let mut seq = 0;
    setup(r, &mut seq, 1, &[0x42; 32], 8, &[], 0);
    finish(r, &mut seq, 1, b"abc", 8, 32, 8);
    seq
}
fn revoked(r: &mut Resident<'_>, seq: u64) {
    // Check revocation before any follow-up could itself revoke the authority.
    // SAFETY: temporary shared authority borrow; no concurrent mutation.
    assert!(unsafe { r.authority.as_ref() }.session().is_err());
    assert!(
        r.execute(CANCEL, &header(seq + 1, 0, 0, 0, 0), &[], |_| panic!(
            "revoked copy"
        ))
        .is_err()
    );
}

#[test]
fn metadata_rejected_before_payload_copy() {
    let cases = [
        (BEGIN, 0, 8),
        (BEGIN, 1, 0),
        (BEGIN, 12, 0),
        (BEGIN, 12, 2),
        (BEGIN, 13, 1),
        (BEGIN, 2, 5),
        (UPDATE, 2, 1),
        (BEGIN, 3, 1),
        (UPDATE, 3, 1025),
        (UPDATE, 5, 0),
        (UPDATE, 5, u64::MAX),
        (BEGIN, 5, 4096),
        (UPDATE, 4, 7),
        (UPDATE, 4, 0),
        (FINISH, 4, 9),
        (BEGIN, 4, 1),
        (BEGIN, 6, 1),
        (FINISH, 6, 8193),
        (SQUEEZE, 6, 1025),
        (SQUEEZE, 4, 0),
        (SQUEEZE, 7, 2),
        (BEGIN, 7, 1),
        (UPDATE, 8, 1),
        (UPDATE, 9, 1),
        (UPDATE, 10, 1),
        (UPDATE, 11, 1),
    ];
    for (op, index, value) in cases {
        let mut h = match op {
            UPDATE | FINISH => header(1, 0, 1, 8, 0),
            SQUEEZE => header(1, 0, 0, 8, 32),
            _ => header(1, 1, 0, 0, 0),
        };
        assert!(Request::decode(op, &h).is_ok());
        field(&mut h, index, value);
        if op == BEGIN && index == 3 {
            field(&mut h, 5, 4096);
        }
        assert!(Request::decode(op, &h).is_err(), "op={op} field={index}");
    }
    for op in [0, 3, 39, 52, usize::MAX] {
        assert!(Request::decode(op, &header(1, 0, 0, 0, 0)).is_err());
    }
    for op in [CUSTOM, KEY, UPDATE, FINISH, VERIFY] {
        let id = u64::from(op == VERIFY);
        assert!(Request::decode(op, &header(1, id, 0, 1, 0)).is_err());
        assert!(Request::decode(op, &header(1, id, 1, 0, 0)).is_err());
    }
    assert!(Request::decode(SQUEEZE, &header(1, 0, 0, 1, 0)).is_err());
}

#[test]
fn decoding_snapshot_copy_and_unwind_failures_revoke() {
    let mut page = Box::new(Page::empty());
    let mut r = Resident::new(&mut page).unwrap();
    let mut seq = 0;
    setup(&mut r, &mut seq, 1, &[0x42; 32], 8, &[], 0);
    assert!(
        r.execute(UPDATE, &header(seq + 1, 0, 3, 8, 0), b"ab", |_| false)
            .is_err()
    );
    revoked(&mut r, seq);
    drop(r);
    cleared(&page);
    for failure in 0..5 {
        let mut page = Box::new(Page::empty());
        let mut r = Resident::new(&mut page).unwrap();
        let seq = retained(&mut r);
        let mut h = header(seq + 1, 1, 0, 8, 32);
        if failure == 0 {
            field(&mut h, 0, 8);
        }
        if failure == 1 {
            field(&mut h, 12, 0);
        }
        let result = catch_unwind(AssertUnwindSafe(|| {
            r.execute(EXPORT, &h, if failure == 2 { b"x" } else { b"" }, |_| {
                if failure == 2 {
                    panic!("unexpected copy");
                }
                if failure == 4 {
                    panic!("copy unwind");
                }
                false
            })
        }));
        if failure == 4 {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        revoked(&mut r, seq + 1);
        drop(r);
        cleared(&page);
    }
}

#[test]
fn verify_only_copies_decision_and_mismatch_is_reusable() {
    let mut source_page = Box::new(Page::empty());
    let mut source = Resident::new(&mut source_page).unwrap();
    let mut seq = retained(&mut source);
    let expected = output(&mut source, &mut seq, 1, 32, 8);
    for failure in 0..4 {
        let mut page = Box::new(Page::empty());
        let mut r = Resident::new(&mut page).unwrap();
        let seq = retained(&mut r);
        let mut candidate = expected.clone();
        if failure == 1 {
            candidate[0] ^= 1;
        }
        let result = catch_unwind(AssertUnwindSafe(|| {
            r.execute(
                VERIFY,
                &header(seq + 1, 1, 32, 8, 0),
                &candidate,
                |decision| {
                    assert_eq!(decision, &[u8::from(failure != 1)]);
                    if failure == 3 {
                        panic!("decision copy unwind");
                    }
                    failure != 2
                },
            )
        }));
        if failure < 2 {
            result.unwrap().unwrap();
            let mut next = seq + 1;
            setup(&mut r, &mut next, 2, &[3; 32], 8, &[], 0);
        } else {
            if failure == 2 {
                assert!(result.unwrap().is_err());
            } else {
                assert!(result.is_err());
            }
            revoked(&mut r, seq + 1);
        }
        drop(r);
        cleared(&page);
    }
}

#[test]
fn every_phase_drop_cancel_and_retained_rekey() {
    for cancel in [false, true] {
        for phase in 0..9 {
            let mut page = Box::new(Page([MaybeUninit::new(0xa5); PAGE_BYTES]));
            let mut r = Resident::new(&mut page).unwrap();
            let mut seq = 1;
            let mut h = header(seq, 3, 0, 0, 0);
            field(&mut h, 8, 256);
            r.execute(BEGIN, &h, &[], |_| false).unwrap();
            if phase >= 1 {
                send(&mut r, &mut seq, CUSTOM_END, 0, &[], 0, 0);
            }
            if phase >= 2 {
                send(&mut r, &mut seq, KEY, 0, &[0x53; 32], 8, 0);
            }
            if phase >= 3 {
                send(&mut r, &mut seq, SETUP_END, 0, &[], 0, 0);
            }
            if phase >= 4 {
                send(&mut r, &mut seq, FINISH, 0, b"abc", 8, 0);
            }
            if phase >= 5 {
                seq += 1;
                let mut h = header(seq, 0, 0, 8, 32);
                field(&mut h, 7, u64::from(phase == 6));
                r.execute(SQUEEZE, &h, &[], |_| false).unwrap();
            }
            if phase >= 7 {
                send(&mut r, &mut seq, REKEY, 2, &[], 0, 0);
            }
            if phase >= 8 {
                send(&mut r, &mut seq, CUSTOM_END, 0, &[], 0, 0);
            }
            if cancel {
                send(&mut r, &mut seq, CANCEL, 0, &[], 0, 0);
                setup(&mut r, &mut seq, 1, &[5; 32], 8, &[], 0);
                r.quarantine();
                revoked(&mut r, seq);
            }
            drop(r);
            cleared(&page);
        }
    }
}
