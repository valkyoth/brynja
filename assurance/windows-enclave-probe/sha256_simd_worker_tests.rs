//! Serialized ordinary-process OS-copy doubles, not VBS admission evidence.
use super::*;
use std::{boxed::Box, sync::Mutex, vec::Vec};
struct Io {
    header: [u8; 288],
    payload: [Vec<u8>; 8],
    output: Vec<u8>,
    fail_kind: usize,
    prefix: usize,
    output_failure: bool,
    observe_failure: bool,
    copies: usize,
    observations: usize,
    alter_header: bool,
}
static IO: Mutex<Io> = Mutex::new(Io {
    header: [0; 288],
    payload: [
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    ],
    output: Vec::new(),
    fail_kind: usize::MAX,
    prefix: 0,
    output_failure: false,
    observe_failure: false,
    copies: 0,
    observations: 0,
    alter_header: false,
});
fn word(index: usize, value: u64) {
    IO.lock().unwrap().header[index * 8..(index + 1) * 8].copy_from_slice(&value.to_le_bytes());
}
fn request(op: usize, sequence: u64, layout: [(u16, usize, u8); 8]) {
    {
        let mut io = IO.lock().unwrap();
        io.header.fill(0);
        io.output.clear();
        io.copies = 0;
        for (lane, (_, size, last)) in layout.iter().copied().enumerate() {
            io.payload[lane] = (0..size)
                .map(|i| ((i * 17 + lane * 29) % 256) as u8)
                .collect();
            if size > 0 {
                io.payload[lane][size - 1] &= 255 << (8 - last);
            }
        }
    }
    word(0, 21);
    word(1, sequence);
    word(2, if op == DIGEST { 1000 } else { 0 });
    word(3, 2);
    for (lane, (code, size, last)) in layout.into_iter().enumerate() {
        word(4 + lane * 4, if op == CANCEL { 0 } else { u64::from(code) });
        if op == DIGEST {
            word(5 + lane * 4, size as u64);
            word(6 + lane * 4, u64::from(last));
            word(7 + lane * 4, 4096 + (lane as u64) * 2048);
        }
    }
}
fn layout() -> [(u16, usize, u8); 8] {
    [
        (224, 65, 7),
        (256, 128, 8),
        (224, 119, 1),
        (256, 1024, 8),
        (256, 120, 2),
        (224, 127, 8),
        (256, 129, 7),
        (224, 1023, 3),
    ]
}
fn invoke(op: usize, page: *mut u8) -> usize {
    let marker = 0_u8;
    let low = (&marker as *const u8).addr() - 32768;
    // SAFETY: one serialized test, valid exclusive pages; synthetic frame window.
    unsafe { RetainedWork(op, page, low, low + 65536, 0) }
}
fn success(op: usize) -> usize {
    op | (1_usize << 32)
}
fn destroy(page: *mut u8) {
    assert_eq!(invoke(3, page), 4);
    // SAFETY: no remaining typed owner; destructor initializes/erases whole page.
    assert!(
        unsafe { core::slice::from_raw_parts(page, 4096) }
            .iter()
            .all(|b| *b == 0)
    );
    assert_eq!(invoke(3, page), 202);
}
fn rejected(page: *mut u8, sequence: u64) {
    IO.lock().unwrap().fail_kind = usize::MAX;
    IO.lock().unwrap().observe_failure = false;
    IO.lock().unwrap().output_failure = false;
    request(CANCEL, sequence, layout());
    assert_eq!(invoke(CANCEL, page), 206, "authority must remain revoked");
    assert!(IO.lock().unwrap().output.is_empty());
    destroy(page);
}
#[test]
fn transport_rejection_copy_boundaries_and_lifecycle() {
    let mut backing = Box::new(Page::empty());
    let page = (&mut *backing as *mut Page).cast::<u8>();
    // Header is a snapshot; subsequent host edits cannot change its meaning.
    assert_eq!(invoke(0, page), 1);
    request(DIGEST, 1, layout());
    IO.lock().unwrap().alter_header = true;
    assert_eq!(invoke(DIGEST, page), success(DIGEST));
    IO.lock().unwrap().alter_header = false;
    request(EXPORT, 2, layout());
    assert_eq!(invoke(EXPORT, page), success(EXPORT));
    assert_eq!(IO.lock().unwrap().output.len(), 256);
    request(DIGEST, 3, layout());
    assert_eq!(invoke(DIGEST, page), success(DIGEST));
    request(CANCEL, 4, layout());
    assert_eq!(invoke(CANCEL, page), success(CANCEL));
    destroy(page);

    // Every prefix, including zero and a complete copy reported as failure.
    for kind in 0..=8 {
        let size = if kind == 0 { 288 } else { layout()[kind - 1].1 };
        for prefix in 0..=size {
            assert_eq!(invoke(0, page), 1);
            request(DIGEST, 1, layout());
            {
                let mut io = IO.lock().unwrap();
                io.fail_kind = kind;
                io.prefix = prefix;
            }
            assert_eq!(invoke(DIGEST, page), 206);
            assert_eq!(IO.lock().unwrap().copies, kind);
            rejected(page, 1);
        }
    }
    // Decode the last lane before copying the first lane, with canonical fields.
    for (index, value) in [
        (0, 20),
        (1, 0),
        (3, 1),
        (32, 0),
        (32, 512),
        (32, 225),
        (33, 0),
        (33, 63),
        (33, 1025),
        (34, 0),
        (34, 9),
        (35, 0),
        (35, u64::MAX),
    ] {
        assert_eq!(invoke(0, page), 1);
        request(DIGEST, 1, layout());
        word(index, value);
        assert_eq!(invoke(DIGEST, page), 206);
        assert_eq!(IO.lock().unwrap().copies, 0);
        rejected(page, 1);
    }
    for operation in [EXPORT, CANCEL, 99, 103] {
        assert_eq!(invoke(0, page), 1);
        request(DIGEST, 1, layout());
        assert_eq!(invoke(operation, page), 206);
        assert_eq!(IO.lock().unwrap().copies, 0);
        rejected(page, 1);
    }
    for mode in 0..8 {
        assert_eq!(invoke(0, page), 1);
        request(DIGEST, 1, layout());
        if mode == 0 {
            word(2, 0);
        }
        if mode == 1 {
            IO.lock().unwrap().payload[0][64] |= 1;
        }
        if mode <= 1 {
            assert_eq!(invoke(DIGEST, page), 206);
            rejected(page, 2);
            continue;
        }
        if mode == 2 {
            IO.lock().unwrap().observe_failure = true;
        }
        assert_eq!(
            invoke(DIGEST, page),
            if mode == 2 { 205 } else { success(DIGEST) }
        );
        if mode == 2 {
            rejected(page, 2);
            continue;
        }
        request(EXPORT, 2, layout());
        if mode == 3 {
            word(1, 1);
        }
        if mode == 4 {
            word(4, 256);
        }
        if mode == 5 {
            IO.lock().unwrap().output_failure = true;
        }
        if mode == 6 {
            word(5, 1);
        }
        if mode == 7 {
            word(2, 1);
        }
        assert_eq!(invoke(EXPORT, page), 206);
        assert!(IO.lock().unwrap().output.is_empty());
        rejected(page, 3);
    }
    assert_eq!(invoke(0, page), 1);
    assert_eq!(invoke(0, page), 201);
    rejected(page, 1);
    assert_eq!(invoke(0, page), 1);
    let mut other = Box::new(Page::empty());
    assert_eq!(invoke(3, (&mut *other as *mut Page).cast()), 203);
    rejected(page, 1);
    assert_eq!(invoke(0, page), 1);
    // SAFETY: invalid span rejected without dereferencing it.
    assert_eq!(unsafe { RetainedWork(DIGEST, page, 1, 2, 0) }, 200);
    rejected(page, 1);
    assert_eq!(invoke(0, page), 1);
    // SAFETY: null page rejected without dereference, revoking live owner.
    assert_eq!(
        unsafe { RetainedWork(DIGEST, core::ptr::null_mut(), 1, 65537, 0) },
        200
    );
    rejected(page, 1);
    assert!(IO.lock().unwrap().observations > 0);
}
#[unsafe(no_mangle)]
extern "C" fn PublicSha256SimdSource() -> usize {
    0x1234
}
#[unsafe(no_mangle)]
extern "C" fn PublicSha256SimdInput(
    kind: usize,
    destination: *mut u8,
    source: usize,
    size: usize,
) -> i32 {
    let mut io = IO.lock().unwrap();
    assert!(kind <= 8);
    if kind > 0 {
        io.copies += 1;
    }
    let input = if kind == 0 {
        assert_eq!(source, 0x1234);
        io.header.as_slice()
    } else {
        assert_eq!(source, 4096 + (kind - 1) * 2048);
        io.payload[kind - 1].as_slice()
    };
    assert_eq!(size, input.len());
    let copied = if io.fail_kind == kind {
        io.prefix
    } else {
        size
    };
    // SAFETY: synchronous exact live destination provided by worker.
    unsafe { core::ptr::copy_nonoverlapping(input.as_ptr(), destination, copied) };
    if kind == 0 && io.alter_header {
        io.header.fill(0xff);
    }
    if io.fail_kind == kind { -1 } else { 0 }
}
#[unsafe(no_mangle)]
extern "C" fn PublicSha256SimdOutput(source: *const u8, size: usize) -> i32 {
    let mut io = IO.lock().unwrap();
    assert_eq!(size, 256);
    if io.output_failure {
        return -1;
    }
    // SAFETY: fixed retained buffer, live for this explicit public export.
    io.output = unsafe { core::slice::from_raw_parts(source, size) }.to_vec();
    0
}
#[unsafe(no_mangle)]
extern "C" fn PublicSha256SimdObserve(header: usize, payload: usize, clear: usize) -> i32 {
    assert_eq!(clear, 1);
    for (address, size) in [(header, 288), (payload, 8192)] {
        // SAFETY: synchronous callback with initialized live worker buffers.
        assert!(
            unsafe { core::slice::from_raw_parts(address as *const u8, size) }
                .iter()
                .all(|b| *b == 0)
        );
    }
    let mut io = IO.lock().unwrap();
    io.observations += 1;
    if io.observe_failure { 0 } else { 1 }
}
