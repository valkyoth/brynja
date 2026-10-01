use super::*;
use brynja_hash_sha3::Fips202BitString;
use std::{
    boxed::Box,
    panic::{AssertUnwindSafe, catch_unwind},
    vec::Vec,
};

fn header(seq: u64, id: u64, len: u64, last: u64, width: u64) -> [u8; 112] {
    encode([
        14,
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
    ])
}
fn encode(words: [u64; 14]) -> [u8; 112] {
    let mut header = [0; 112];
    for (slot, value) in header.chunks_exact_mut(8).zip(words) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
    header
}
fn field(header: &mut [u8; 112], index: usize, value: u64) {
    header[index * 8..(index + 1) * 8].copy_from_slice(&value.to_le_bytes());
}
fn cleared(page: &Page) {
    for byte in &page.0 {
        // SAFETY: Resident was dropped and must initialize the entire page by
        // clearing it. The separate Miri model checks this memory invariant.
        assert_eq!(unsafe { byte.assume_init() }, 0);
    }
}
fn retained(resident: &mut Resident<'_>) {
    resident
        .execute(21, &header(1, 2, 0, 0, 0), &[], |_| panic!("begin copy"))
        .unwrap();
    resident
        .execute(23, &header(2, 0, 3, 8, 0), b"abc", |_| {
            panic!("finish copy")
        })
        .unwrap();
}
fn revoked(resident: &mut Resident<'_>) {
    assert!(
        resident
            .execute(25, &header(3, 2, 0, 8, 32), &[], |_| panic!("revoked copy"))
            .is_err()
    );
    // SAFETY: test-only temporary shared borrow; no mutable authority exists.
    assert!(unsafe { resident.authority.as_ref() }.session().is_err());
}

#[test]
fn placement_recreation_and_all_eight_wire_identities() {
    let mut page = Box::new(Page([MaybeUninit::new(0xa5); PAGE_BYTES]));
    let base = page.0.as_ptr().addr();
    for id in 1..=8 {
        let mut resident = Resident::new(&mut page).unwrap();
        assert_eq!(resident.authority.as_ptr().addr(), base);
        assert_eq!(resident.owner.as_ptr().addr(), base + OWNER_OFFSET);
        let empty = Fips202BitString::new(&[], 0).unwrap();
        let mut scalar = sha3_stream::Owner::new();
        scalar.begin(1, id, empty, empty).unwrap();
        resident
            .execute(21, &header(1, id, 0, 0, 0), &[], |_| panic!("begin copy"))
            .unwrap();
        scalar.update(2, b"ab").unwrap();
        resident
            .execute(22, &header(2, 0, 2, 8, 0), b"ab", |_| panic!("update copy"))
            .unwrap();
        scalar.finish(3, b"c", 7).unwrap();
        resident
            .execute(23, &header(3, 0, 1, 7, 0), b"c", |_| panic!("finish copy"))
            .unwrap();
        let (width, last, seq) = if id <= 4 {
            ([28, 32, 48, 64][(id - 1) as usize], 8, 4)
        } else {
            scalar.squeeze(4, 333, 3, true).unwrap();
            let mut request = header(4, 0, 0, 3, 333);
            field(&mut request, 7, 1);
            resident
                .execute(27, &request, &[], |_| panic!("squeeze copy"))
                .unwrap();
            (333, 3, 5)
        };
        let mut expected = Vec::new();
        scalar
            .export_public(seq, id, width as usize, last, |b| {
                expected.extend_from_slice(b);
                true
            })
            .unwrap();
        resident
            .execute(25, &header(seq, id, 0, u64::from(last), width), &[], |b| {
                assert_eq!(b, expected);
                true
            })
            .unwrap();
        drop(resident);
        cleared(&page);
    }
}

#[test]
fn streamed_prefix_incremental_xof_and_retained_rehash() {
    for id in [7, 8] {
        let mut page = Box::new(Page::empty());
        let mut resident = Resident::new(&mut page).unwrap();
        let mut scalar = sha3_stream::Owner::new();
        let mut request = header(1, id, 0, 0, 0);
        field(&mut request, 8, 11);
        field(&mut request, 10, 3);
        scalar.setup(1, id, 11, 3).unwrap();
        resident
            .execute(28, &request, &[], |_| panic!("setup copy"))
            .unwrap();
        for (seq, op, input, last) in [
            (2, 29, &[0xa5][..], 8),
            (3, 29, &[3][..], 3),
            (4, 30, &[5][..], 3),
        ] {
            scalar.setup_chunk(seq, op == 29, input, last).unwrap();
            resident
                .execute(op, &header(seq, 0, 1, u64::from(last), 0), input, |_| {
                    panic!("prefix copy")
                })
                .unwrap();
        }
        scalar.finish_setup(5).unwrap();
        resident
            .execute(31, &header(5, 0, 0, 0, 0), &[], |_| false)
            .unwrap();
        scalar.finish(6, b"abc", 7).unwrap();
        resident
            .execute(23, &header(6, 0, 3, 7, 0), b"abc", |_| false)
            .unwrap();
        // A nonterminal fragment must preserve the exact XOF position.
        scalar.squeeze(7, 169, 8, false).unwrap();
        resident
            .execute(27, &header(7, 0, 0, 8, 169), &[], |_| false)
            .unwrap();
        let mut expected = Vec::new();
        scalar
            .export_public(8, id, 169, 8, |b| {
                expected.extend_from_slice(b);
                true
            })
            .unwrap();
        resident
            .execute(25, &header(8, id, 0, 8, 169), &[], |b| {
                assert_eq!(b, expected);
                true
            })
            .unwrap();
        let mut request = header(9, 0, 0, 3, 27);
        field(&mut request, 7, 1);
        scalar.squeeze(9, 27, 3, true).unwrap();
        resident.execute(27, &request, &[], |_| false).unwrap();
        let empty = Fips202BitString::new(&[], 0).unwrap();
        scalar.rehash(10, 2, empty, empty).unwrap();
        resident
            .execute(24, &header(10, 2, 0, 0, 0), &[], |_| panic!("rehash copy"))
            .unwrap();
        expected.clear();
        scalar
            .export_public(11, 2, 32, 8, |b| {
                expected.extend_from_slice(b);
                true
            })
            .unwrap();
        resident
            .execute(25, &header(11, 2, 0, 8, 32), &[], |b| {
                assert_eq!(b, expected);
                true
            })
            .unwrap();
        drop(resident);
        cleared(&page);
    }
}

#[test]
fn decoder_rejects_noncanonical_metadata_before_payload_copy() {
    let cases = [
        (21, 0, 7),
        (21, 0, 13),
        (21, 1, 0),
        (21, 12, 0),
        (21, 12, 2),
        (21, 13, 1),
        (21, 2, 9),
        (28, 2, 2),
        (22, 2, 1),
        (21, 3, 1),
        (22, 3, 1025),
        (22, 5, 0),
        (22, 5, u64::MAX),
        (21, 5, 4096),
        (22, 4, 7),
        (22, 4, 0),
        (23, 4, 9),
        (21, 4, 1),
        (21, 6, 1),
        (27, 6, 1025),
        (27, 4, 0),
        (25, 4, 9),
        (27, 7, 2),
        (21, 7, 1),
        (21, 8, 1),
        (21, 9, 1),
        (21, 10, 1),
        (21, 11, 1),
    ];
    for (op, index, value) in cases {
        let mut request = match op {
            22 | 23 => header(1, 0, 1, 8, 0),
            25 => header(1, 2, 0, 8, 32),
            27 => header(1, 0, 0, 8, 32),
            28 => header(1, 7, 0, 0, 0),
            _ => header(1, 2, 0, 0, 0),
        };
        assert!(Request::decode(op, &request).is_ok());
        field(&mut request, index, value);
        if op == 21 && index == 3 {
            field(&mut request, 5, 4096);
        }
        assert!(
            Request::decode(op, &request).is_err(),
            "op={op} field={index} value={value}"
        );
    }
    for op in [0, 3, 20, 32, usize::MAX] {
        assert!(Request::decode(op, &header(1, 0, 0, 0, 0)).is_err());
    }
    for op in [23, 29, 30] {
        assert!(Request::decode(op, &header(1, 0, 0, 1, 0)).is_err());
        assert!(Request::decode(op, &header(1, 0, 1, 0, 0)).is_err());
    }
    assert!(Request::decode(27, &header(1, 0, 0, 1, 0)).is_err());
}

#[test]
fn decode_snapshot_copy_and_unwind_failures_revoke_retained_state() {
    for failure in 0..5 {
        let mut page = Box::new(Page::empty());
        let mut resident = Resident::new(&mut page).unwrap();
        retained(&mut resident);
        let mut request = header(3, 2, 0, 8, 32);
        if failure == 0 {
            field(&mut request, 0, 7);
        }
        if failure == 1 {
            field(&mut request, 12, 0);
        }
        let result = catch_unwind(AssertUnwindSafe(|| {
            resident.execute(25, &request, if failure == 2 { b"x" } else { b"" }, |_| {
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
        revoked(&mut resident);
        drop(resident);
        cleared(&page);
    }
}

#[test]
fn every_live_phase_drops_and_cancel_preserves_reuse() {
    for cancel in [false, true] {
        for phase in 0..6 {
            let mut page = Box::new(Page([MaybeUninit::new(0xa5); PAGE_BYTES]));
            let mut resident = Resident::new(&mut page).unwrap();
            let mut seq = 1;
            if phase == 0 {
                let mut request = header(seq, 7, 0, 0, 0);
                field(&mut request, 8, 500);
                resident.execute(28, &request, &[], |_| false).unwrap();
            } else {
                let id = if phase >= 3 { 5 } else { 2 };
                resident
                    .execute(21, &header(seq, id, 0, 0, 0), &[], |_| false)
                    .unwrap();
                seq += 1;
                resident
                    .execute(
                        if phase == 1 { 22 } else { 23 },
                        &header(seq, 0, 3, 8, 0),
                        b"abc",
                        |_| false,
                    )
                    .unwrap();
                if phase >= 4 {
                    seq += 1;
                    let mut request = header(seq, 0, 0, 8, 17);
                    field(&mut request, 7, u64::from(phase == 5));
                    resident.execute(27, &request, &[], |_| false).unwrap();
                }
            }
            if cancel {
                resident
                    .execute(26, &header(seq + 1, 0, 0, 0, 0), &[], |_| false)
                    .unwrap();
                resident
                    .execute(21, &header(seq + 2, 2, 0, 0, 0), &[], |_| false)
                    .unwrap();
                resident.quarantine();
                assert!(
                    resident
                        .execute(26, &header(seq + 3, 0, 0, 0, 0), &[], |_| false)
                        .is_err()
                );
            }
            drop(resident);
            cleared(&page);
        }
    }
}
