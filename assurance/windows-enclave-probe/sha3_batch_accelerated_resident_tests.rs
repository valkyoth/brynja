use super::*;
use sha3_batch_accelerated::{Slot, sha3_batch_accelerated_wire::*};
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
    plan: [Slot; 8],
) -> [u8; HEADER_BYTES] {
    let mut h = [0; HEADER_BYTES];
    for (index, value) in [
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
        field(&mut h, index, value);
    }
    field(&mut h, 36, 1);
    if matches!(op, BEGIN | EXPORT) {
        for (index, s) in plan.into_iter().enumerate() {
            field(&mut h, 12 + index * 3, s.identity);
            field(&mut h, 13 + index * 3, s.width as u64);
            field(&mut h, 14 + index * 3, s.last as u64);
        }
    }
    h
}
fn single() -> [Slot; 8] {
    let mut p = [Slot::default(); 8];
    p[0] = Slot {
        identity: 2,
        width: 32,
        last: 8,
    };
    p
}
fn send(r: &mut Resident<'_>, seq: &mut u64, op: usize, mut h: [u8; HEADER_BYTES], input: &[u8]) {
    *seq = seq.checked_add(1).unwrap();
    field(&mut h, 1, *seq);
    r.execute(op, &h, input, |_| panic!("unexpected export"))
        .unwrap();
}
fn cleared(page: &Page) {
    for byte in &page.0 {
        // SAFETY: resident destruction initialized and erased the complete page.
        assert_eq!(unsafe { byte.assume_init() }, 0);
    }
}
fn revoked(r: &mut Resident<'_>) {
    // SAFETY: shared access to the placed authority, with no concurrent writer.
    assert!(unsafe { r.authority.as_ref() }.session().is_err());
    assert!(
        r.execute(
            CANCEL,
            &header(CANCEL, 100, 0, &[], 0, single()),
            &[],
            |_| panic!()
        )
        .is_err()
    );
}
fn retain(r: &mut Resident<'_>) -> u64 {
    let mut n = 0;
    for (op, input, last) in [
        (BEGIN, &b""[..], 0),
        (START, &b""[..], 0),
        (SETUP, &b""[..], 0),
        (FINISH, &b"abc"[..], 8),
        (SEAL, &b""[..], 0),
    ] {
        send(
            r,
            &mut n,
            op,
            header(op, 1, 0, input, last, single()),
            input,
        );
    }
    n
}
fn hex(value: &str) -> Vec<u8> {
    if value == "-" {
        return Vec::new();
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|part| u8::from_str_radix(core::str::from_utf8(part).unwrap(), 16).unwrap())
        .collect()
}
fn tail(bits: usize) -> u8 {
    if bits == 0 {
        0
    } else {
        ((bits - 1) % 8 + 1) as u8
    }
}
fn fragments(
    r: &mut Resident<'_>,
    seq: &mut u64,
    op: usize,
    data: &[u8],
    bits: usize,
    plan: [Slot; 8],
) {
    let mut start = 0;
    while start < bits {
        let count = 37.min(bits - start);
        let mut buffer = [0; 5];
        for bit in 0..count {
            buffer[bit / 8] |= ((data[(start + bit) / 8] >> ((start + bit) % 8)) & 1) << (bit % 8);
        }
        let input = &buffer[..count.div_ceil(8)];
        send(
            r,
            seq,
            op,
            header(op, 1, 0, input, tail(count), plan),
            input,
        );
        start += count;
    }
}
#[test]
fn independent_oracles_through_placed_wire_and_full_page_erasure() {
    let mut count = 0;
    for row in include_str!("sha3-batch-oracle.txt").lines() {
        let f: Vec<_> = row.split_whitespace().collect();
        let id = f[0].parse().unwrap();
        let nb: usize = f[1].parse().unwrap();
        let sb: usize = f[3].parse().unwrap();
        let mb: usize = f[5].parse().unwrap();
        let ob: usize = f[7].parse().unwrap();
        let (name, custom, message, expected) = (hex(f[2]), hex(f[4]), hex(f[6]), hex(f[8]));
        let mut plan = [Slot::default(); 8];
        plan[0] = Slot {
            identity: id,
            width: ob.div_ceil(8),
            last: tail(ob),
        };
        let mut page = Box::new(Page([MaybeUninit::new(0xa5); PAGE_BYTES]));
        let address = page.0.as_ptr().addr();
        let mut r = Resident::new(&mut page).unwrap();
        assert_eq!(r.authority.as_ptr().addr(), address);
        assert_eq!(r.owner.as_ptr().addr(), address + OWNER_OFFSET);
        let mut seq = 0;
        send(
            &mut r,
            &mut seq,
            BEGIN,
            header(BEGIN, 1, 0, &[], 0, plan),
            &[],
        );
        let mut h = header(START, 1, 0, &[], 0, plan);
        field(&mut h, 8, nb as u64);
        field(&mut h, 10, sb as u64);
        send(&mut r, &mut seq, START, h, &[]);
        if id >= 7 {
            fragments(&mut r, &mut seq, NAME, &name, nb, plan);
            fragments(&mut r, &mut seq, CUSTOM, &custom, sb, plan);
        }
        send(
            &mut r,
            &mut seq,
            SETUP,
            header(SETUP, 1, 0, &[], 0, plan),
            &[],
        );
        let split = message.len().saturating_sub(1);
        for chunk in message[..split].chunks(113) {
            send(
                &mut r,
                &mut seq,
                UPDATE,
                header(UPDATE, 1, 0, chunk, 8, plan),
                chunk,
            );
        }
        let final_bytes = &message[split..];
        send(
            &mut r,
            &mut seq,
            FINISH,
            header(FINISH, 1, 0, final_bytes, tail(mb), plan),
            final_bytes,
        );
        send(
            &mut r,
            &mut seq,
            SEAL,
            header(SEAL, 1, 0, &[], 0, plan),
            &[],
        );
        r.execute(
            EXPORT,
            &header(EXPORT, seq + 1, 0, &[], 0, plan),
            &[],
            |bytes| {
                assert_eq!(&bytes[..expected.len()], expected);
                assert!(bytes[expected.len()..].iter().all(|b| *b == 0));
                true
            },
        )
        .unwrap();
        drop(r);
        cleared(&page);
        count += 1;
    }
    assert_eq!(count, 604);
}
#[test]
fn metadata_payload_copy_unwind_and_revocation_fail_closed() {
    for failure in 0..9 {
        let mut page = Box::new(Page::empty());
        let mut r = Resident::new(&mut page).unwrap();
        let n = retain(&mut r);
        let mut h = header(EXPORT, n + 1, 0, &[], 0, single());
        match failure {
            0 => field(&mut h, 0, 11),
            1 => field(&mut h, 36, 0),
            2 => field(&mut h, 37, 1),
            3 => field(&mut h, 12, 1),
            7 => r.quarantine(),
            _ => (),
        }
        let result = catch_unwind(AssertUnwindSafe(|| {
            r.execute(EXPORT, &h, if failure == 4 { b"x" } else { b"" }, |_| {
                if failure == 6 {
                    panic!("copy failure");
                }
                failure == 8
            })
        }));
        if failure == 8 {
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
fn cancel_reuse_and_drop_with_retained_and_active_slots() {
    for mode in 0..3 {
        let mut page = Box::new(Page([MaybeUninit::new(0x5a); PAGE_BYTES]));
        let mut r = Resident::new(&mut page).unwrap();
        let mut plan = single();
        plan[1] = Slot {
            identity: 8,
            width: 137,
            last: 3,
        };
        let mut n = 0;
        send(
            &mut r,
            &mut n,
            BEGIN,
            header(BEGIN, 1, 0, &[], 0, plan),
            &[],
        );
        for slot in 0..2 {
            send(
                &mut r,
                &mut n,
                START,
                header(START, 1, slot, &[], 0, plan),
                &[],
            );
            send(
                &mut r,
                &mut n,
                SETUP,
                header(SETUP, 1, slot, &[], 0, plan),
                &[],
            );
            send(
                &mut r,
                &mut n,
                UPDATE,
                header(UPDATE, 1, slot, b"retained bytes", 8, plan),
                b"retained bytes",
            );
            if slot == 0 {
                send(
                    &mut r,
                    &mut n,
                    FINISH,
                    header(FINISH, 1, slot, &[], 0, plan),
                    &[],
                );
            }
        }
        if mode == 1 {
            send(
                &mut r,
                &mut n,
                CANCEL,
                header(CANCEL, 1, 0, &[], 0, plan),
                &[],
            );
            send(
                &mut r,
                &mut n,
                BEGIN,
                header(BEGIN, 1, 0, &[], 0, plan),
                &[],
            );
        } else if mode == 2 {
            r.quarantine();
            revoked(&mut r);
        }
        drop(r);
        cleared(&page);
        // The erased allocation is reusable only after both placed lifetimes end.
        drop(Resident::new(&mut page).unwrap());
        cleared(&page);
    }
}
