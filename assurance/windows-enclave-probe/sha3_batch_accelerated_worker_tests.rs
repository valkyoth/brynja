//! Ordinary-process OS-copy doubles; never native admission evidence.
use super::*;
use std::{boxed::Box, sync::Mutex, vec::Vec};
struct Io {
    header: [u8; 304],
    payload: Vec<u8>,
    output: Vec<u8>,
    failure: usize,
    payload_copies: usize,
    observations: usize,
}
static IO: Mutex<Io> = Mutex::new(Io {
    header: [0; 304],
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
        17,
        seq,
        identity,
        data.len() as u64,
        last,
        if data.is_empty() { 0 } else { 4096 },
    ]) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
    io.header[288..296].copy_from_slice(&1_u64.to_le_bytes());
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
    word(12, 2);
    word(13, 32);
    word(14, 8);
}
fn ready(page: *mut u8) {
    request(1, 0, &[], 0);
    word(6, 3);
    plan();
    assert_eq!(invoke(90, page), success(90));
    request(2, 0, &[], 0);
    assert_eq!(invoke(91, page), success(91));
    request(3, 0, &[], 0);
    assert_eq!(invoke(94, page), success(94));
}
fn finish(page: *mut u8) {
    request(4, 0, b"abc", 8);
    assert_eq!(invoke(96, page), success(96));
    request(5, 0, &[], 0);
    assert_eq!(invoke(97, page), success(97));
}
fn export_request() {
    request(6, 0, &[], 0);
    plan();
}
#[test]
fn serialized_worker_snapshots_errors_receipts_and_destruction() {
    // FIPS 202 SHA3-256("abc"), public known-answer vector.
    let expected = [
        0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90,
        0xbd, 0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43,
        0x15, 0x32,
    ];
    let mut backing = Box::new(Page::empty());
    let page = (&mut *backing as *mut Page).cast::<u8>();
    assert_eq!(invoke(0, page), 1);
    ready(page);
    finish(page);
    export_request();
    assert_eq!(invoke(98, page), success(98));
    {
        let io = IO.lock().unwrap();
        assert_eq!(&io.output[..32], expected);
        assert_eq!(io.output.len(), 1024);
        assert!(io.output[32..].iter().all(|b| *b == 0));
    }
    destroy(page);
    for failure in 1..=8 {
        assert_eq!(invoke(0, page), 1);
        ready(page);
        request(4, 0, b"abc", 8);
        let operation = if failure == 3 {
            finish(page);
            export_request();
            98
        } else {
            96
        };
        IO.lock().unwrap().failure = failure;
        if failure == 5 {
            IO.lock().unwrap().header[0] = 8;
        }
        if failure == 6 {
            IO.lock().unwrap().header[288] = 0;
        }
        assert!(matches!(invoke(operation, page), 205 | 206));
        if matches!(failure, 1 | 5 | 6 | 7) {
            assert_eq!(IO.lock().unwrap().payload_copies, 0);
        }
        IO.lock().unwrap().failure = 0;
        // Use the actual next sequence so revocation, not replay, is exercised.
        request(
            if failure == 3 {
                7
            } else if failure == 4 {
                5
            } else {
                4
            },
            0,
            &[],
            0,
        );
        assert_eq!(invoke(99, page), 206);
        export_request();
        assert_eq!(invoke(98, page), 206);
        assert!(IO.lock().unwrap().output.is_empty());
        destroy(page);
    }
    assert_eq!(invoke(0, page), 1);
    assert_eq!(invoke(0, page), 201);
    request(1, 0, &[], 0);
    word(6, 3);
    plan();
    assert_eq!(invoke(90, page), 206);
    destroy(page);
    assert_eq!(invoke(0, page), 1);
    let mut other = Box::new(Page::empty());
    assert_eq!(invoke(3, (&mut *other as *mut Page).cast()), 203);
    request(1, 0, &[], 0);
    word(6, 3);
    plan();
    assert_eq!(invoke(90, page), 206);
    destroy(page);
    assert_eq!(invoke(0, page), 1);
    // SAFETY: invalid stack span rejected without accessing it; page valid.
    assert_eq!(unsafe { RetainedWork(90, page, 1, 2, 0) }, 200);
    destroy(page);
    assert!(IO.lock().unwrap().observations > 0);
}
#[unsafe(no_mangle)]
extern "C" fn PublicSha3BatchSource() -> usize {
    0x1234
}
#[unsafe(no_mangle)]
extern "C" fn PublicSha3BatchInput(
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
extern "C" fn PublicSha3BatchOutput(source: *const u8, size: usize) -> i32 {
    let mut io = IO.lock().unwrap();
    if io.failure == 3 {
        return -1;
    }
    // SAFETY: worker supplies a live exact digest slice, only at explicit export.
    io.output = unsafe { core::slice::from_raw_parts(source, size) }.to_vec();
    0
}
#[unsafe(no_mangle)]
extern "C" fn PublicSha3BatchObserve(header: usize, payload: usize, cleared: usize) -> i32 {
    assert_eq!(cleared, 1);
    // SAFETY: callbacks are synchronous, buffers still initialized and live.
    assert!(
        unsafe { core::slice::from_raw_parts(header as *const u8, 304) }
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
