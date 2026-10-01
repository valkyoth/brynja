//! Ordinary-process OS-copy doubles; never native admission evidence.
use super::*;
use std::{boxed::Box, sync::Mutex, vec::Vec};
struct Io {
    header: [u8; 64],
    payload: Vec<u8>,
    output: Vec<u8>,
    failure: usize,
    payload_copies: usize,
    observations: usize,
}
static IO: Mutex<Io> = Mutex::new(Io {
    header: [0; 64],
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
    for (slot, value) in io.header.chunks_exact_mut(8).zip([
        13,
        seq,
        identity,
        data.len() as u64,
        last,
        if data.is_empty() { 0 } else { 4096 },
        1,
        0,
    ]) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
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

#[test]
fn serialized_worker_snapshots_errors_receipts_and_destruction() {
    let mut backing = Box::new(Page::empty());
    let page = (&mut *backing as *mut Page).cast::<u8>();
    assert_eq!(invoke(0, page), 1);
    request(1, 2, &[], 0);
    assert_eq!(invoke(11, page), success(11));
    request(2, 0, b"abc", 8);
    assert_eq!(invoke(13, page), success(13));
    request(3, 2, &[], 0);
    assert_eq!(invoke(15, page), success(15));
    assert_eq!(
        IO.lock().unwrap().output,
        brynja_hash_sha2::sha256(b"abc").unwrap().as_bytes()
    );
    destroy(page);
    for failure in 1..=8 {
        assert_eq!(invoke(0, page), 1);
        request(1, 1, &[], 0);
        assert_eq!(invoke(11, page), success(11));
        request(2, 0, b"abc", 8);
        IO.lock().unwrap().failure = failure;
        let operation = if failure == 3 {
            IO.lock().unwrap().failure = 0;
            assert_eq!(invoke(13, page), success(13));
            request(3, 1, &[], 0);
            IO.lock().unwrap().failure = 3;
            15
        } else {
            13
        };
        if failure == 5 {
            IO.lock().unwrap().header[0] = 6;
        }
        if failure == 6 {
            IO.lock().unwrap().header[48] = 0;
        }
        assert!(matches!(invoke(operation, page), 205 | 206));
        if matches!(failure, 1 | 5 | 6 | 7) {
            assert_eq!(IO.lock().unwrap().payload_copies, 0);
        }
        IO.lock().unwrap().failure = 0;
        // Cancellation would succeed on a still-live streaming/retained owner.
        // Use its actual next sequence, not an accidental sequence-error oracle.
        request(if failure == 4 { 3 } else { 2 }, 0, &[], 0);
        assert_eq!(invoke(16, page), 206);
        request(3, 1, &[], 0);
        assert_eq!(invoke(15, page), 206);
        assert!(IO.lock().unwrap().output.is_empty());
        destroy(page);
    }
    assert_eq!(invoke(0, page), 1);
    assert_eq!(invoke(0, page), 201);
    request(1, 2, &[], 0);
    assert_eq!(invoke(11, page), 206);
    destroy(page);
    assert_eq!(invoke(0, page), 1);
    let mut other = Box::new(Page::empty());
    assert_eq!(invoke(3, (&mut *other as *mut Page).cast()), 203);
    request(1, 2, &[], 0);
    assert_eq!(invoke(11, page), 206);
    destroy(page);
    assert_eq!(invoke(0, page), 1);
    // SAFETY: invalid stack span is rejected without accessing it; page valid.
    assert_eq!(unsafe { RetainedWork(11, page, 1, 2, 0) }, 200);
    destroy(page);
    assert!(IO.lock().unwrap().observations > 0);
}
#[unsafe(no_mangle)]
extern "C" fn PublicSha2Source() -> usize {
    0x1234
}
#[unsafe(no_mangle)]
extern "C" fn PublicSha2Input(
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
extern "C" fn PublicSha2Output(source: *const u8, size: usize) -> i32 {
    let mut io = IO.lock().unwrap();
    if io.failure == 3 {
        return -1;
    }
    // SAFETY: worker supplies a live exact digest slice, only at explicit export.
    io.output = unsafe { core::slice::from_raw_parts(source, size) }.to_vec();
    0
}
#[unsafe(no_mangle)]
extern "C" fn PublicSha2Observe(header: usize, payload: usize, cleared: usize) -> i32 {
    assert_eq!(cleared, 1);
    // SAFETY: callbacks are synchronous, buffers still initialized and live.
    assert!(
        unsafe { core::slice::from_raw_parts(header as *const u8, 64) }
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
