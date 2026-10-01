use super::*;
use parallel_accelerated::parallel_accelerated_wire::*;
use std::{
    boxed::Box,
    panic::{AssertUnwindSafe, catch_unwind},
    vec::Vec,
};

fn field(header: &mut [u8; HEADER_BYTES], index: usize, value: u64) {
    header[index * 8..(index + 1) * 8].copy_from_slice(&value.to_le_bytes());
}
fn header(seq: u64, input: &[u8], last: u8) -> [u8; HEADER_BYTES] {
    let mut h = [0; HEADER_BYTES];
    for (index, value) in [
        (0, VERSION),
        (1, seq),
        (7, input.len() as u64),
        (8, last as u64),
        (12, if input.is_empty() { 0 } else { 4096 }),
        (14, 1),
    ] {
        field(&mut h, index, value);
    }
    h
}
fn send(r: &mut Resident<'_>, seq: &mut u64, op: usize, mut h: [u8; HEADER_BYTES], input: &[u8]) {
    *seq = seq.checked_add(1).unwrap();
    field(&mut h, 1, *seq);
    r.execute(op, &h, input, |_| panic!("unexpected export"))
        .unwrap();
}
fn cleared(page: &Page) {
    for byte in &page.0 {
        // SAFETY: destruction initialized and erased every backing byte.
        assert_eq!(unsafe { byte.assume_init() }, 0);
    }
}
fn revoked(r: &mut Resident<'_>) {
    // SAFETY: shared access with no concurrent operation or writer.
    assert!(unsafe { r.authority.as_ref() }.session().is_err());
    assert!(
        r.execute(CANCEL, &header(100, &[], 0), &[], |_| panic!())
            .is_err()
    );
}
fn begin(r: &mut Resident<'_>, seq: &mut u64, id: u64, block: u64, custom: u64) {
    let mut h = header(1, &[], 0);
    for (i, n) in [(2, id), (3, block), (4, u64::MAX), (5, custom)] {
        field(&mut h, i, n);
    }
    send(r, seq, BEGIN, h, &[]);
}
fn retain(r: &mut Resident<'_>) -> u64 {
    let mut seq = 0;
    begin(r, &mut seq, 1, 8, 0);
    send(r, &mut seq, SETUP, header(1, &[], 0), &[]);
    let mut h = header(1, b"abc", 8);
    field(&mut h, 9, 32);
    field(&mut h, 10, 8);
    send(r, &mut seq, FINISH, h, b"abc");
    seq
}
fn export(seq: u64, id: u64, width: usize, last: u8) -> [u8; HEADER_BYTES] {
    let mut h = header(seq, &[], 0);
    field(&mut h, 2, id);
    field(&mut h, 9, width as u64);
    field(&mut h, 10, last as u64);
    h
}
fn hex(value: &str) -> Vec<u8> {
    if value == "-" {
        return Vec::new();
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn tail(bits: usize) -> u8 {
    if bits == 0 {
        0
    } else {
        ((bits - 1) % 8 + 1) as u8
    }
}

#[test]
fn independent_oracles_through_placed_wire_and_full_page_erasure() {
    let mut count = 0;
    for row in include_str!("parallel-vectors.txt")
        .lines()
        .filter(|line| line.starts_with("D "))
    {
        let f: Vec<_> = row.split_whitespace().collect();
        let id = f[1].parse().unwrap();
        let block = f[2].parse().unwrap();
        let cb: usize = f[3].parse().unwrap();
        let mb: usize = f[4].parse().unwrap();
        let last: u8 = f[5].parse().unwrap();
        let (custom, message, expected) = (hex(f[6]), hex(f[7]), hex(f[8]));
        let mut page = Box::new(Page([MaybeUninit::new(0xa5); PAGE_BYTES]));
        let address = page.0.as_ptr().addr();
        let mut r = Resident::new(&mut page).unwrap();
        assert_eq!(r.authority.as_ptr().addr(), address);
        assert_eq!(r.owner.as_ptr().addr(), address + OWNER_OFFSET);
        let mut seq = 0;
        begin(&mut r, &mut seq, id, block, cb as u64);
        let mut start = 0;
        while start < cb {
            let n = (cb - start).min(37);
            let mut bytes = [0; 5];
            for bit in 0..n {
                bytes[bit / 8] |=
                    ((custom[(start + bit) / 8] >> ((start + bit) % 8)) & 1) << (bit % 8);
            }
            let input = &bytes[..n.div_ceil(8)];
            send(&mut r, &mut seq, CUSTOM, header(1, input, tail(n)), input);
            start += n;
        }
        send(&mut r, &mut seq, SETUP, header(1, &[], 0), &[]);
        let split = message.len().saturating_sub(1);
        for chunk in message[..split].chunks(113) {
            send(&mut r, &mut seq, UPDATE, header(1, chunk, 8), chunk);
        }
        let rest = &message[split..];
        let mut h = header(1, rest, tail(mb));
        if id <= 2 {
            field(&mut h, 9, expected.len() as u64);
            field(&mut h, 10, last as u64);
        }
        send(&mut r, &mut seq, FINISH, h, rest);
        if id > 2 {
            let mut h = header(1, &[], 0);
            field(&mut h, 9, expected.len() as u64);
            field(&mut h, 10, last as u64);
            field(&mut h, 11, 1);
            send(&mut r, &mut seq, SQUEEZE, h, &[]);
        }
        r.execute(
            EXPORT,
            &export(seq + 1, id, expected.len(), last),
            &[],
            |bytes| {
                assert_eq!(bytes, expected);
                true
            },
        )
        .unwrap();
        drop(r);
        cleared(&page);
        count += 1;
    }
    assert_eq!(count, 332);
}

#[test]
fn metadata_payload_copy_unwind_and_revocation_fail_closed() {
    for failure in 0..9 {
        let mut page = Box::new(Page::empty());
        let mut r = Resident::new(&mut page).unwrap();
        let seq = retain(&mut r);
        let mut h = export(seq + 1, 1, 32, 8);
        match failure {
            0 => field(&mut h, 0, 12),
            1 => field(&mut h, 14, 0),
            2 => field(&mut h, 15, 1),
            3 => field(&mut h, 2, 2),
            7 => r.quarantine(),
            _ => (),
        }
        let result = catch_unwind(AssertUnwindSafe(|| {
            r.execute(EXPORT, &h, if failure == 4 { b"x" } else { b"" }, |_| {
                if failure == 6 {
                    panic!("copy unwind");
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
fn cancel_reuse_and_drop_with_active_root_leaf_and_retained_output() {
    for mode in 0..4 {
        let mut page = Box::new(Page([MaybeUninit::new(0x5a); PAGE_BYTES]));
        let mut r = Resident::new(&mut page).unwrap();
        let mut seq = 0;
        if mode == 0 {
            retain(&mut r);
        } else {
            begin(&mut r, &mut seq, 1, 8, 0);
            send(&mut r, &mut seq, SETUP, header(1, &[], 0), &[]);
            send(&mut r, &mut seq, UPDATE, header(1, b"abc", 8), b"abc");
            if mode == 2 {
                send(&mut r, &mut seq, CANCEL, header(1, &[], 0), &[]);
                begin(&mut r, &mut seq, 3, 7, 13);
            } else if mode == 3 {
                r.quarantine();
                revoked(&mut r);
            }
        }
        drop(r);
        cleared(&page);
        drop(Resident::new(&mut page).unwrap());
        cleared(&page);
    }
}
