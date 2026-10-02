//! Serialized ordinary-process OS-copy doubles, not VBS admission evidence.
use super::*;
use std::{boxed::Box, sync::Mutex, vec::Vec};
pub(super) struct Io {
    header: [u8; 384],
    pub(super) payload: [Vec<u8>; 12],
    pub(super) output: Vec<u8>,
    fail_kind: usize,
    prefix: usize,
    output_failure: bool,
    observe_failure: bool,
    copies: usize,
    observations: usize,
    alter_header: bool,
}
pub(super) static IO: Mutex<Io> = Mutex::new(Io {
    header: [0; 384],
    payload: [const { Vec::new() }; 12],
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
// identity, output bits, message bits, name bits, customization bits.
pub(super) type Layout = [(u8, usize, usize, usize, usize); 4];
fn canonical(seed: u32, bits: usize) -> Vec<u8> {
    let mut state = seed;
    let mut bytes: Vec<_> = (0..bits.div_ceil(8))
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state & 255) as u8
        })
        .collect();
    if bits % 8 != 0 {
        *bytes.last_mut().unwrap() &= (1 << (bits % 8)) - 1;
    }
    bytes
}
pub(super) fn request(op: usize, sequence: u64, layout: Layout) {
    {
        let mut io = IO.lock().unwrap();
        io.header.fill(0);
        io.output.clear();
        io.copies = 0;
        for (lane, (_, _, mb, nb, sb)) in layout.iter().copied().enumerate() {
            for (part, (seed, bits)) in [
                (11 + lane * 31, mb),
                (19 + lane * 17, nb),
                (23 + lane * 13, sb),
            ]
            .into_iter()
            .enumerate()
            {
                io.payload[lane * 3 + part] = canonical(seed as u32, bits);
            }
        }
    }
    word(0, 22);
    word(1, sequence);
    word(2, if op == DIGEST { 1000 } else { 0 });
    word(3, 2);
    for (lane, (code, output, mb, nb, sb)) in layout.into_iter().enumerate() {
        if op == CANCEL {
            continue;
        }
        word(4 + lane * 11, u64::from(code));
        word(5 + lane * 11, output as u64);
        if op != DIGEST {
            continue;
        }
        for (part, bits) in [mb, nb, sb].into_iter().enumerate() {
            if bits == 0 {
                continue;
            }
            word(6 + lane * 11 + part * 3, bits.div_ceil(8) as u64);
            word(7 + lane * 11 + part * 3, (1 + (bits - 1) % 8) as u64);
            word(
                8 + lane * 11 + part * 3,
                (4096 + (lane * 3 + part) * 2048) as u64,
            );
        }
    }
}
fn layout() -> Layout {
    [
        (7, 257, 519, 49, 71),
        (8, 2048, 1088, 1024, 8192),
        (7, 1, 8192, 1, 1079),
        (8, 0, 1, 8192, 17),
    ]
}
fn lengths() -> [usize; 12] {
    let mut bits = [0; 12];
    for (lane, (_, _, mb, nb, sb)) in layout().into_iter().enumerate() {
        bits[lane * 3..lane * 3 + 3].copy_from_slice(&[mb, nb, sb]);
    }
    bits
}
pub(super) fn invoke(op: usize, page: *mut u8) -> usize {
    let marker = 0_u8;
    let low = (&marker as *const u8).addr() - 32768;
    // SAFETY: one serialized test, valid exclusive pages; synthetic frame window.
    unsafe { RetainedWork(op, page, low, low + 65536, 0) }
}
pub(super) fn success(op: usize) -> usize {
    op | (1_usize << 32)
}
pub(super) fn destroy(page: *mut u8) {
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
    assert_eq!(IO.lock().unwrap().output.len(), 1024);
    request(DIGEST, 3, layout());
    assert_eq!(invoke(DIGEST, page), success(DIGEST));
    request(CANCEL, 4, layout());
    assert_eq!(invoke(CANCEL, page), success(CANCEL));
    destroy(page);

    // Every prefix, including zero and a complete copy reported as failure.
    for kind in 0..=12 {
        let size = if kind == 0 {
            384
        } else {
            lengths()[kind - 1].div_ceil(8)
        };
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
        (0, 21),
        (1, 0),
        (3, 1),
        (37, 0),
        (37, 9),
        (37, 2),
        (38, 2049),
        (39, 0),
        (39, 1025),
        (40, 0),
        (40, 9),
        (41, 0),
        (41, u64::MAX),
        (42, 1025),
        (43, 9),
        (44, 0),
        (45, 1025),
        (46, 9),
        (47, 0),
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
            IO.lock().unwrap().payload[0][64] |= 128;
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
            word(4, 8);
        }
        if mode == 5 {
            IO.lock().unwrap().output_failure = true;
        }
        if mode == 6 {
            word(6, 1);
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
extern "C" fn PublicKeccakSimdSource() -> usize {
    0x1234
}
#[unsafe(no_mangle)]
extern "C" fn PublicKeccakSimdInput(
    kind: usize,
    destination: *mut u8,
    source: usize,
    size: usize,
) -> i32 {
    let mut io = IO.lock().unwrap();
    assert!(kind <= 12);
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
extern "C" fn PublicKeccakSimdOutput(source: *const u8, size: usize) -> i32 {
    let mut io = IO.lock().unwrap();
    assert_eq!(size, 1024);
    if io.output_failure {
        return -1;
    }
    // SAFETY: fixed retained buffer, live for this explicit public export.
    io.output = unsafe { core::slice::from_raw_parts(source, size) }.to_vec();
    0
}
#[unsafe(no_mangle)]
extern "C" fn PublicKeccakSimdObserve(header: usize, payload: usize, clear: usize) -> i32 {
    assert_eq!(clear, 1);
    for (address, size) in [(header, 384), (payload, 12288)] {
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
