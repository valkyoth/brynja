//! Ordinary-process OS-copy doubles; never native admission evidence.
use super::*;
use std::{boxed::Box, sync::Mutex, vec::Vec};
struct Io {
    header: [u8; 144],
    payload: Vec<u8>,
    output: Vec<u8>,
    failure: usize,
    payload_copies: usize,
    observations: usize,
}
static IO: Mutex<Io> = Mutex::new(Io {
    header: [0; 144],
    payload: Vec::new(),
    output: Vec::new(),
    failure: 0,
    payload_copies: 0,
    observations: 0,
});
fn request(seq: u64, identity: u64, data: &[u8], last: u64) {
    let mut io = IO.lock().unwrap();
    io.payload = data.to_vec();
    io.output.clear();
    io.payload_copies = 0;
    io.header.fill(0);
    for (slot, value) in io.header.chunks_exact_mut(8).zip([
        19,
        seq,
        identity,
        data.len() as u64,
        last,
        if data.is_empty() { 0 } else { 4096 },
    ]) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
    io.header[128..136].copy_from_slice(&1_u64.to_le_bytes());
}
fn invoke(op: usize, page: *mut u8) -> usize {
    let marker = 0_u8;
    let low = (&marker as *const u8).addr() - 32768;
    // SAFETY: one sequential test owns aligned live pages and never releases a
    // live owner; declared stack span contains this synchronous test frame.
    unsafe { RetainedWork(op, page, low, low + 65536, 0) }
}
fn success(op: usize) -> usize {
    op | (1_usize << 32)
}
fn destroy(page: *mut u8) {
    assert_eq!(invoke(3, page), 4);
    // SAFETY: destructor initialized every backing byte; no typed borrow remains.
    assert!(
        unsafe { core::slice::from_raw_parts(page, 4096) }
            .iter()
            .all(|b| *b == 0)
    );
    assert_eq!(invoke(3, page), 202);
}

fn word(index: usize, value: u64) {
    IO.lock().unwrap().header[index * 8..(index + 1) * 8].copy_from_slice(&value.to_le_bytes());
}
fn plan() {
    word(8, 2);
}
fn ready(page: *mut u8) {
    request(1, 0, &[], 0);
    word(6, 3);
    plan();
    assert_eq!(invoke(80, page), success(80));
    request(2, 0, &[], 0);
    assert_eq!(invoke(81, page), success(81));
}
fn finish(page: *mut u8) {
    request(3, 0, b"abc", 8);
    assert_eq!(invoke(83, page), success(83));
    request(4, 0, &[], 0);
    assert_eq!(invoke(84, page), success(84));
}
fn export_request() {
    request(5, 0, &[], 0);
    plan();
}
#[test]
fn serialized_worker_snapshots_errors_receipts_and_destruction() {
    // FIPS 180-4 SHA-256("abc"), public known-answer vector.
    let expected = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    let mut backing = Box::new(Page::empty());
    let page = (&mut *backing as *mut Page).cast::<u8>();
    assert_eq!(invoke(0, page), 1);
    ready(page);
    finish(page);
    export_request();
    assert_eq!(invoke(85, page), success(85));
    {
        let io = IO.lock().unwrap();
        assert_eq!(&io.output[..32], expected);
        assert_eq!(io.output.len(), 512);
        assert!(io.output[32..].iter().all(|b| *b == 0));
    }
    destroy(page);
    for failure in 1..=8 {
        assert_eq!(invoke(0, page), 1);
        ready(page);
        request(3, 0, b"abc", 8);
        let operation = if failure == 3 {
            finish(page);
            export_request();
            85
        } else {
            83
        };
        IO.lock().unwrap().failure = failure;
        if failure == 5 {
            IO.lock().unwrap().header[0] = 8;
        }
        if failure == 6 {
            IO.lock().unwrap().header[128] = 0;
        }
        assert!(matches!(invoke(operation, page), 205 | 206));
        if matches!(failure, 1 | 5 | 6 | 7) {
            assert_eq!(IO.lock().unwrap().payload_copies, 0);
        }
        IO.lock().unwrap().failure = 0;
        // Use the actual next sequence so revocation, not replay, is exercised.
        request(
            if failure == 3 {
                6
            } else if failure == 4 {
                4
            } else {
                3
            },
            0,
            &[],
            0,
        );
        assert_eq!(invoke(86, page), 206);
        export_request();
        assert_eq!(invoke(85, page), 206);
        assert!(IO.lock().unwrap().output.is_empty());
        destroy(page);
    }
    assert_eq!(invoke(0, page), 1);
    assert_eq!(invoke(0, page), 201);
    request(1, 0, &[], 0);
    word(6, 3);
    plan();
    assert_eq!(invoke(80, page), 206);
    destroy(page);
    assert_eq!(invoke(0, page), 1);
    let mut other = Box::new(Page::empty());
    assert_eq!(invoke(3, (&mut *other as *mut Page).cast()), 203);
    request(1, 0, &[], 0);
    word(6, 3);
    plan();
    assert_eq!(invoke(80, page), 206);
    destroy(page);
    assert_eq!(invoke(0, page), 1);
    // SAFETY: invalid stack span rejected without accessing it; page valid.
    assert_eq!(unsafe { RetainedWork(80, page, 1, 2, 0) }, 200);
    destroy(page);
    assert!(IO.lock().unwrap().observations > 0);
}
#[unsafe(no_mangle)]
extern "C" fn PublicSha2BatchSource() -> usize {
    0x1234
}
#[unsafe(no_mangle)]
extern "C" fn PublicSha2BatchInput(
    kind: usize,
    destination: *mut u8,
    source: usize,
    size: usize,
) -> i32 {
    let mut io = IO.lock().unwrap();
    if kind == 1 {
        io.payload_copies += 1;
    }
    let input = if kind == 0 {
        assert_eq!(source, 0x1234);
        io.header.as_slice()
    } else {
        assert_eq!(kind, 1);
        assert_eq!(source, 4096);
        io.payload.as_slice()
    };
    assert_eq!(size, input.len());
    // SAFETY: worker provides the exact exclusive bounded live destination.
    // Partial copy failures exercise clearing after OS-style incomplete output.
    let copied = if io.failure == kind + 1 {
        size / 2
    } else {
        size
    };
    unsafe {
        core::ptr::copy_nonoverlapping(input.as_ptr(), destination, copied);
    }
    if io.failure == kind + 1 || io.failure == kind + 7 {
        -1
    } else {
        0
    }
}
#[unsafe(no_mangle)]
extern "C" fn PublicSha2BatchOutput(source: *const u8, size: usize) -> i32 {
    let mut io = IO.lock().unwrap();
    if io.failure == 3 {
        return -1;
    }
    // SAFETY: worker supplies a live exact digest slice, only at explicit export.
    io.output = unsafe { core::slice::from_raw_parts(source, size) }.to_vec();
    0
}
#[unsafe(no_mangle)]
extern "C" fn PublicSha2BatchObserve(header: usize, payload: usize, cleared: usize) -> i32 {
    assert_eq!(cleared, 1);
    // SAFETY: callbacks are synchronous, buffers still initialized and live.
    assert!(
        unsafe { core::slice::from_raw_parts(header as *const u8, 144) }
            .iter()
            .all(|b| *b == 0)
    );
    assert!(
        unsafe { core::slice::from_raw_parts(payload as *const u8, 1024) }
            .iter()
            .all(|b| *b == 0)
    );
    let mut io = IO.lock().unwrap();
    io.observations += 1;
    if io.failure == 4 { 0 } else { 1 }
}
