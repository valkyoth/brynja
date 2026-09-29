extern crate std;
use brynja_hash_sha2::hardened_in_place::Sha256Workspace;
use core::mem::MaybeUninit;
use persistent_result::{Error as SlotError, PUBLIC_OUTPUT};
use retained_borrowed::*;
use retained_input::{CAPACITY, HEADER, Request};
use retained_placement::Placed;
use std::panic::{AssertUnwindSafe, catch_unwind};

#[repr(align(4096))]
struct Page([MaybeUninit<u8>; 4096]);
fn header(words: [u64; 4]) -> [u8; HEADER] {
    let mut out = [0; HEADER];
    for (word, bytes) in words.into_iter().zip(out.chunks_exact_mut(8)) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    out
}
fn zero(workspace: &Sha256Workspace) {
    // SAFETY: builder's existing layout check binds initialized byte-array fields,
    // size and alignment with no padding; no mutable workspace borrow is live.
    let bytes =
        unsafe { core::slice::from_raw_parts(core::ptr::from_ref(workspace).cast::<u8>(), 1170) };
    assert!(
        bytes
            .iter()
            .all(|byte| unsafe { core::ptr::read_volatile(byte) == 0 })
    );
}
fn oracle(input: &[u8], expected: &[u8; 32]) {
    let mut page = Page([MaybeUninit::new(0); 4096]);
    let mut owner = Placed::new(&mut page.0, [7, 9]).unwrap();
    let token = {
        let mut workspace = Sha256Workspace::new();
        let mut snapshot = [0xa5; CAPACITY];
        let mut staging = [0xa5; 32];
        let request = Request::new(input, 11).unwrap();
        let mut copies = 0;
        let token = compute(
            &mut owner,
            &mut workspace,
            &mut snapshot,
            &mut staging,
            request.metadata(),
            11,
            |address, out| {
                copies += 1;
                assert_eq!(address, input.as_ptr() as u64);
                assert_eq!(out.len(), input.len());
                out.copy_from_slice(input);
                true
            },
        )
        .unwrap();
        assert_eq!(copies, usize::from(!input.is_empty()));
        assert_eq!(snapshot, [0; CAPACITY]);
        assert_eq!(staging, [0; 32]);
        zero(&workspace);
        token
    };
    let mut output = [0xcc; 32];
    owner
        .export_public(token, PUBLIC_OUTPUT, |bytes| {
            output.copy_from_slice(bytes);
            true
        })
        .unwrap();
    assert_eq!(output, *expected);
    assert_eq!(owner.cancel(token), Err(SlotError::Spent));
    drop(owner);
    assert!(page.0.iter().all(|byte| unsafe { byte.assume_init() } == 0));
}

#[test]
fn descriptor_rejects_bounds_versions_sequences_and_pointer_overflow() {
    assert_eq!(core::mem::size_of::<Request>(), HEADER);
    assert!(Request::new(&[0; CAPACITY + 1], 1).is_err());
    assert!(Request::new(&[], 0).is_err());
    for words in [
        [3, 11, 1, 4096],
        [4, 0, 1, 4096],
        [4, 12, 1, 4096],
        [4, 11, 1025, 4096],
        [4, 11, 1, 0],
        [4, 11, 0, 4096],
        [4, 11, 1, u64::MAX],
    ] {
        assert!(retained_input::admit(&header(words), 11).is_err());
    }
    assert!(retained_input::admit(&header([4, 0, 0, 0]), 0).is_err());
    assert_eq!(
        retained_input::admit(&header([4, 11, 0, 0]), 11),
        Ok((0, 0))
    );
    assert_eq!(
        retained_input::admit(&header([4, u64::MAX, 1024, 4096]), u64::MAX),
        Ok((4096, 1024))
    );
}

#[test]
fn rejected_header_clears_full_capacity_without_copy_and_quarantines() {
    let mut page = Page([MaybeUninit::new(0); 4096]);
    let mut owner = Placed::new(&mut page.0, [7, 9]).unwrap();
    let mut workspace = Sha256Workspace::new();
    let mut snapshot = [0xa5; CAPACITY];
    let mut staging = [0xa5; 32];
    assert_eq!(
        compute(
            &mut owner,
            &mut workspace,
            &mut snapshot,
            &mut staging,
            &header([4, 12, 1, 4096]),
            11,
            |_, _| panic!("invalid header reached OS copy")
        ),
        Err(Error::Header)
    );
    assert_eq!(snapshot, [0; CAPACITY]);
    assert_eq!(staging, [0; 32]);
    zero(&workspace);
    assert_eq!(
        owner.hash(&mut workspace, &mut staging, b"reuse"),
        Err(SlotError::Quarantined)
    );
}

#[test]
fn every_partial_copy_error_or_unwind_clears_and_quarantines() {
    for copied in [0, 1, 17, 63, 64, 1023, 1024] {
        for unwind in [false, true] {
            let mut page = Page([MaybeUninit::new(0); 4096]);
            let mut owner = Placed::new(&mut page.0, [7, 9]).unwrap();
            let mut workspace = Sha256Workspace::new();
            let mut snapshot = [0xa5; CAPACITY];
            let mut staging = [0xa5; 32];
            let result = catch_unwind(AssertUnwindSafe(|| {
                compute(
                    &mut owner,
                    &mut workspace,
                    &mut snapshot,
                    &mut staging,
                    &header([4, 11, 1024, 4096]),
                    11,
                    |_, out| {
                        out[..copied].fill(0x5a);
                        if unwind {
                            panic!("OS copy seam unwind");
                        }
                        false
                    },
                )
            }));
            assert_eq!(result.is_err(), unwind);
            if let Ok(value) = result {
                assert_eq!(value, Err(Error::Copy));
            }
            assert_eq!(snapshot, [0; CAPACITY]);
            assert_eq!(staging, [0; 32]);
            zero(&workspace);
            assert_eq!(
                owner.hash(&mut workspace, &mut staging, b"reuse"),
                Err(SlotError::Quarantined)
            );
        }
    }
}

#[test]
fn unexpected_busy_attempt_clears_both_input_and_preexisting_result() {
    let mut page = Page([MaybeUninit::new(0); 4096]);
    let mut owner = Placed::new(&mut page.0, [7, 9]).unwrap();
    let mut workspace = Sha256Workspace::new();
    let mut snapshot = [0xa5; CAPACITY];
    let mut staging = [0xa5; 32];
    let token = owner
        .hash(&mut workspace, &mut staging, b"old result")
        .unwrap();
    assert_eq!(
        compute(
            &mut owner,
            &mut workspace,
            &mut snapshot,
            &mut staging,
            &header([4, 11, 1, 4096]),
            11,
            |_, out| {
                out.fill(42);
                true
            }
        ),
        Err(Error::Owner(SlotError::Busy))
    );
    assert_eq!(snapshot, [0; CAPACITY]);
    assert_eq!(staging, [0; 32]);
    zero(&workspace);
    assert_eq!(
        owner.export_public(token, PUBLIC_OUTPUT, |_| panic!(
            "quarantine exported old result"
        )),
        Err(SlotError::Quarantined)
    );
}

#[test]
fn caller_input_can_change_after_return_without_changing_retained_result() {
    let mut page = Page([MaybeUninit::new(0); 4096]);
    let mut owner = Placed::new(&mut page.0, [7, 9]).unwrap();
    let mut input = *b"abc";
    let token = {
        let request = Request::new(&input, 11).unwrap();
        let mut workspace = Sha256Workspace::new();
        let mut snapshot = [0xa5; CAPACITY];
        let mut staging = [0xa5; 32];
        compute(
            &mut owner,
            &mut workspace,
            &mut snapshot,
            &mut staging,
            request.metadata(),
            11,
            |_, out| {
                out.copy_from_slice(&input);
                true
            },
        )
        .unwrap()
    };
    input.fill(0);
    let mut output = [0; 32];
    owner
        .export_public(token, PUBLIC_OUTPUT, |bytes| {
            output.copy_from_slice(bytes);
            true
        })
        .unwrap();
    assert_eq!(input, [0; 3]);
    assert_eq!(
        output,
        [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad
        ]
    );
}
