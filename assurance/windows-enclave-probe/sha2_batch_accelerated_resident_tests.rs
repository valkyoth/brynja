use super::*;
use sha2_batch_accelerated::sha2_batch_accelerated_wire::*;
use std::{
    boxed::Box,
    panic::{AssertUnwindSafe, catch_unwind},
    vec::Vec,
};

fn field(header: &mut [u8; HEADER_BYTES], index: usize, value: u64) {
    header[index * 8..(index + 1) * 8].copy_from_slice(&value.to_le_bytes());
}
fn header(
    op: usize,
    seq: u64,
    slot: usize,
    input: &[u8],
    last: u8,
    plan: [u64; 8],
) -> [u8; HEADER_BYTES] {
    let mut h = [0; HEADER_BYTES];
    for (i, value) in [
        VERSION,
        seq,
        slot as u64,
        input.len() as u64,
        last as u64,
        if input.is_empty() { 0 } else { 4096 },
        if op == BEGIN { u64::MAX } else { 0 },
    ]
    .into_iter()
    .enumerate()
    {
        field(&mut h, i, value);
    }
    if matches!(op, BEGIN | EXPORT) {
        for (i, id) in plan.into_iter().enumerate() {
            field(&mut h, i + 8, id);
        }
    }
    field(&mut h, 16, 1);
    h
}
fn send(
    r: &mut Resident<'_>,
    seq: &mut u64,
    op: usize,
    slot: usize,
    input: &[u8],
    last: u8,
    plan: [u64; 8],
) {
    *seq = seq.checked_add(1).unwrap();
    r.execute(
        op,
        &header(op, *seq, slot, input, last, plan),
        input,
        |_| panic!("unexpected export"),
    )
    .unwrap();
}
fn cleared(page: &Page) {
    for byte in &page.0 {
        // SAFETY: after resident destruction, every byte must be initialized by
        // the full-page wipe. The separate Miri model checks this premise.
        assert_eq!(unsafe { byte.assume_init() }, 0);
    }
}
fn hex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn single() -> [u64; 8] {
    [2, 0, 0, 0, 0, 0, 0, 0]
}
fn retain(r: &mut Resident<'_>) -> u64 {
    let mut n = 0;
    send(r, &mut n, BEGIN, 0, &[], 0, single());
    send(r, &mut n, START, 0, &[], 0, single());
    send(r, &mut n, FINISH, 0, b"abc", 8, single());
    send(r, &mut n, SEAL, 0, &[], 0, single());
    n
}
fn revoked(r: &mut Resident<'_>) {
    // SAFETY: test-only shared access to the still-live placed authority. No
    // concurrent operation or mutable reference exists; this borrow ends here.
    assert!(unsafe { r.authority.as_ref() }.session().is_err());
    assert!(
        r.execute(
            EXPORT,
            &header(EXPORT, 5, 0, &[], 0, single()),
            &[],
            |_| panic!("revoked output")
        )
        .is_err()
    );
}

#[test]
fn independent_bits_mixed_slots_and_full_page_erasure() {
    let mut count = 0;
    for row in include_str!("sha2-batch-resident-oracle.txt").lines() {
        let f: Vec<_> = row.split_whitespace().collect();
        let id = f[0].parse().unwrap();
        let last = f[1].parse().unwrap();
        let (message, expected) = (hex(f[2]), hex(f[3]));
        let mut page = Box::new(Page([MaybeUninit::new(0xa5); PAGE_BYTES]));
        let base = page.0.as_ptr().addr();
        let mut r = Resident::new(&mut page).unwrap();
        assert_eq!(r.authority.as_ptr().addr(), base);
        assert_eq!(r.owner.as_ptr().addr(), base + OWNER_OFFSET);
        let plan = [id; 8];
        let mut n = 0;
        send(&mut r, &mut n, BEGIN, 0, &[], 0, plan);
        for slot in 0..8 {
            send(&mut r, &mut n, START, slot, &[], 0, plan);
            let split = message.len().saturating_sub(1);
            for chunk in message[..split].chunks(113) {
                send(&mut r, &mut n, UPDATE, slot, &[], 0, plan);
                send(&mut r, &mut n, UPDATE, slot, chunk, 8, plan);
            }
            send(&mut r, &mut n, FINISH, slot, &message[split..], last, plan);
        }
        send(&mut r, &mut n, SEAL, 0, &[], 0, plan);
        r.execute(
            EXPORT,
            &header(EXPORT, n + 1, 0, &[], 0, plan),
            &[],
            |bytes| {
                for slot in bytes.chunks_exact(64) {
                    assert_eq!(&slot[..expected.len()], expected);
                    assert!(slot[expected.len()..].iter().all(|b| *b == 0));
                }
                true
            },
        )
        .unwrap();
        drop(r);
        cleared(&page);
        count += 1;
    }
    assert_eq!(count, 242);
    for mask in 1_u16..=255 {
        let plan = core::array::from_fn(|i| {
            if mask & (1 << i) != 0 {
                1 + i as u64 % 2
            } else {
                0
            }
        });
        let mut page = Box::new(Page::empty());
        let mut r = Resident::new(&mut page).unwrap();
        let mut n = 0;
        send(&mut r, &mut n, BEGIN, 0, &[], 0, plan);
        for slot in 0..8 {
            if plan[slot] == 0 {
                continue;
            }
            send(&mut r, &mut n, START, slot, &[], 0, plan);
            send(&mut r, &mut n, FINISH, slot, &[slot as u8; 3], 8, plan);
        }
        send(&mut r, &mut n, SEAL, 0, &[], 0, plan);
        r.execute(
            EXPORT,
            &header(EXPORT, n + 1, 0, &[], 0, plan),
            &[],
            |bytes| {
                for (slot, output) in bytes.chunks_exact(64).enumerate() {
                    let expected = match plan[slot] {
                        0 => Vec::new(),
                        1 => brynja_hash_sha2::sha224(&[slot as u8; 3])
                            .unwrap()
                            .as_bytes()
                            .to_vec(),
                        2 => brynja_hash_sha2::sha256(&[slot as u8; 3])
                            .unwrap()
                            .as_bytes()
                            .to_vec(),
                        _ => panic!("test plan"),
                    };
                    assert_eq!(&output[..expected.len()], expected);
                    assert!(output[expected.len()..].iter().all(|b| *b == 0));
                }
                true
            },
        )
        .unwrap();
        drop(r);
        cleared(&page);
    }
}

#[test]
fn malformed_metadata_copy_unwind_and_revocation_clear_and_quarantine() {
    for failure in 0..10 {
        let mut page = Box::new(Page([MaybeUninit::new(0x5a); PAGE_BYTES]));
        let mut r = Resident::new(&mut page).unwrap();
        let n = retain(&mut r);
        let mut h = header(EXPORT, n + 1, 0, &[], 0, single());
        match failure {
            0 => field(&mut h, 0, 10),
            1 => field(&mut h, 16, 0),
            2 => field(&mut h, 17, 1),
            3 => field(&mut h, 8, 1),
            7 => {
                r.quarantine();
                revoked(&mut r);
            }
            8 => {
                // SAFETY: shared authority operation, no overlapping writer.
                unsafe { r.authority.as_ref() }.quarantine();
            }
            _ => (),
        }
        let result = catch_unwind(AssertUnwindSafe(|| {
            r.execute(EXPORT, &h, if failure == 4 { b"x" } else { b"" }, |_| {
                if failure == 6 {
                    panic!("copy failure");
                }
                failure == 9
            })
        }));
        if failure == 9 {
            result.unwrap().unwrap();
        } else {
            if failure == 6 {
                assert!(result.is_err());
            } else {
                assert!(result.unwrap().is_err());
            }
            revoked(&mut r);
        }
        drop(r);
        cleared(&page);
    }
}

#[test]
fn retained_plus_active_drop_cancel_reuse_and_recreation() {
    let mut page = Box::new(Page([MaybeUninit::new(0xa5); PAGE_BYTES]));
    for cancel in [false, true] {
        let mut r = Resident::new(&mut page).unwrap();
        let plan = [1, 2, 0, 0, 0, 0, 0, 0];
        let mut n = 0;
        send(&mut r, &mut n, BEGIN, 0, &[], 0, plan);
        send(&mut r, &mut n, START, 0, &[], 0, plan);
        send(&mut r, &mut n, FINISH, 0, b"abc", 8, plan);
        send(&mut r, &mut n, START, 1, &[], 0, plan);
        send(&mut r, &mut n, UPDATE, 1, b"not yet finished", 8, plan);
        if cancel {
            send(&mut r, &mut n, CANCEL, 0, &[], 0, plan);
            send(&mut r, &mut n, BEGIN, 0, &[], 0, single());
            send(&mut r, &mut n, START, 0, &[], 0, single());
            send(&mut r, &mut n, FINISH, 0, b"abc", 8, single());
            send(&mut r, &mut n, SEAL, 0, &[], 0, single());
            r.execute(
                EXPORT,
                &header(EXPORT, n + 1, 0, &[], 0, single()),
                &[],
                |bytes| {
                    assert_eq!(
                        &bytes[..32],
                        brynja_hash_sha2::sha256(b"abc").unwrap().as_bytes()
                    );
                    assert!(bytes[32..].iter().all(|b| *b == 0));
                    true
                },
            )
            .unwrap();
        }
        drop(r);
        cleared(&page);
    }
}
