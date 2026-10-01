//! Ordinary-process OS-copy doubles; never native admission evidence.
use super::*;
use std::{boxed::Box, sync::Mutex, vec::Vec};
struct Io {
    header: [u8; 128],
    payload: Vec<u8>,
    output: Vec<u8>,
    failure: usize,
    payload_copies: usize,
    observations: usize,
}
static IO: Mutex<Io> = Mutex::new(Io {
    header: [0; 128],
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
        18,
        seq,
        identity,
        if identity == 1 { 8 } else { 0 },
        if identity == 1 { 3 } else { 0 },
        0,
        0,
        data.len() as u64,
        last,
        0,
        0,
        0,
        if data.is_empty() { 0 } else { 4096 },
        0,
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

fn word(index: usize, value: u64) {
    IO.lock().unwrap().header[index * 8..(index + 1) * 8].copy_from_slice(&value.to_le_bytes());
}
fn ready(page: *mut u8) {
    request(1, 1, &[], 0);
    assert_eq!(invoke(100, page), success(100));
    request(2, 0, &[], 0);
    assert_eq!(invoke(102, page), success(102));
}
fn finish(page: *mut u8) {
    request(3, 0, b"abc", 8);
    assert_eq!(invoke(103, page), success(103));
    request(4, 0, &[], 0);
    word(9, 32);
    word(10, 8);
    assert_eq!(invoke(104, page), success(104));
}
fn export_request() {
    request(5, 1, &[], 0);
    word(3, 0);
    word(4, 0);
    word(9, 32);
    word(10, 8);
}
#[test]
fn serialized_worker_snapshots_errors_receipts_and_destruction() {
    // Independent Python SP 800-185 oracle, ParallelHash128("abc", B=8, "", 256).
    let expected = [
        16, 226, 82, 72, 165, 181, 239, 140, 251, 188, 176, 249, 209, 76, 126, 23, 134, 208, 163,
        162, 48, 65, 151, 251, 209, 53, 22, 23, 220, 126, 116, 168,
    ];
    let mut backing = Box::new(Page::empty());
    let page = (&mut *backing as *mut Page).cast::<u8>();
    assert_eq!(invoke(0, page), 1);
    ready(page);
    finish(page);
    export_request();
    assert_eq!(invoke(106, page), success(106));
    assert_eq!(IO.lock().unwrap().output, expected);
    destroy(page);
    for failure in 1..=8 {
        assert_eq!(invoke(0, page), 1);
        ready(page);
        request(3, 0, b"abc", 8);
        let operation = if failure == 3 {
            finish(page);
            export_request();
            106
        } else {
            103
        };
        IO.lock().unwrap().failure = failure;
        if failure == 5 {
            IO.lock().unwrap().header[0] = 8;
        }
        if failure == 6 {
            IO.lock().unwrap().header[112] = 0;
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
        assert_eq!(invoke(107, page), 206);
        export_request();
        assert_eq!(invoke(106, page), 206);
        assert!(IO.lock().unwrap().output.is_empty());
        destroy(page);
    }
    assert_eq!(invoke(0, page), 1);
    assert_eq!(invoke(0, page), 201);
    request(1, 1, &[], 0);
    assert_eq!(invoke(100, page), 206);
    destroy(page);
    assert_eq!(invoke(0, page), 1);
    let mut other = Box::new(Page::empty());
    assert_eq!(invoke(3, (&mut *other as *mut Page).cast()), 203);
    request(1, 1, &[], 0);
    assert_eq!(invoke(100, page), 206);
    destroy(page);
    assert_eq!(invoke(0, page), 1);
    // SAFETY: invalid stack span rejected without accessing it; page valid.
    assert_eq!(unsafe { RetainedWork(100, page, 1, 2, 0) }, 200);
    destroy(page);
    assert!(IO.lock().unwrap().observations > 0);
}
#[unsafe(no_mangle)]
extern "C" fn PublicParallelSource() -> usize {
    0x1234
}
#[unsafe(no_mangle)]
extern "C" fn PublicParallelInput(
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
extern "C" fn PublicParallelOutput(source: *const u8, size: usize) -> i32 {
    let mut io = IO.lock().unwrap();
    if io.failure == 3 {
        return -1;
    }
    // SAFETY: worker supplies a live exact digest slice, only at explicit export.
    io.output = unsafe { core::slice::from_raw_parts(source, size) }.to_vec();
    0
}
#[unsafe(no_mangle)]
extern "C" fn PublicParallelObserve(header: usize, payload: usize, cleared: usize) -> i32 {
    assert_eq!(cleared, 1);
    // SAFETY: callbacks are synchronous, buffers still initialized and live.
    assert!(
        unsafe { core::slice::from_raw_parts(header as *const u8, 128) }
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
