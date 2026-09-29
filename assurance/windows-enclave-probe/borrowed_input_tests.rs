extern crate std;
use super::*;
use brynja_hash_sha2::hardened_in_place::Sha256Workspace;
use std::{
    cell::Cell,
    panic::{AssertUnwindSafe, catch_unwind},
};

fn word(header: &mut [u8; HEADER], index: usize, value: u64) {
    header[index * 8..index * 8 + 8].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn every_length_has_one_bounded_copy_no_reread_and_full_cleanup() {
    let input = [0xa5; CAPACITY];
    let mut snapshot = Snapshot::new();
    for length in 0..=CAPACITY {
        snapshot.bytes.fill(0x5a);
        let request = Request::new(&input[..length], 0x1000).unwrap();
        let calls = Cell::new(0);
        let result = snapshot.with(
            request.metadata(),
            |source, destination| {
                assert_eq!(source, input.as_ptr() as u64);
                assert_eq!(destination.len(), length);
                calls.set(calls.get() + 1);
                destination.fill(if calls.get() == 1 { 0xa5 } else { 0xff });
                true
            },
            |bytes, command| {
                assert_eq!(command, 0x1000);
                assert_eq!(bytes, &input[..length]);
                bytes.len()
            },
        );
        assert_eq!(result, Ok(length));
        assert_eq!(calls.get(), usize::from(length != 0));
        assert!(snapshot.bytes.iter().all(|byte| *byte == 0));
    }
}

#[test]
fn copy_errors_partial_writes_and_both_unwind_paths_clear_capacity() {
    let input = [0xa5; CAPACITY];
    let request = Request::new(&input, 0x1000).unwrap();
    for written in [0, 1, 32, 511, 1024] {
        let mut snapshot = Snapshot::new();
        snapshot.bytes.fill(9);
        let called = Cell::new(false);
        assert_eq!(
            snapshot.with(
                request.metadata(),
                |_, out| {
                    out[..written].fill(0xaa);
                    false
                },
                |_, _| {
                    called.set(true);
                }
            ),
            Err(Error::Copy)
        );
        assert!(!called.get());
        assert!(snapshot.bytes.iter().all(|byte| *byte == 0));
    }
    for copy_panic in [true, false] {
        let mut snapshot = Snapshot::new();
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _ = snapshot.with(
                request.metadata(),
                |_, out| {
                    out.fill(0xa5);
                    if copy_panic {
                        panic!("controlled OS-copy model unwind");
                    }
                    true
                },
                |_, _| {
                    panic!("controlled worker-model unwind");
                },
            );
        }));
        assert!(result.is_err());
        assert!(snapshot.bytes.iter().all(|byte| *byte == 0));
    }
}

#[test]
fn malformed_metadata_never_copies_or_enters_worker_and_clears() {
    let input = [7; 8];
    let request = Request::new(&input, 0x1000).unwrap();
    for (index, value) in [
        (0, 2),
        (1, 1),
        (2, 1025),
        (2, 0),
        (3, 0),
        (3, u64::MAX - 4),
        (4, 0),
        (4, u64::MAX - 63),
        (5, 63),
        (6, 1),
        (7, 1),
    ] {
        let mut header = *request.metadata();
        word(&mut header, index, value);
        let mut snapshot = Snapshot::new();
        snapshot.bytes.fill(0xa5);
        assert_eq!(
            snapshot.with(
                &header,
                |_, _| panic!("invalid read"),
                |_, _| panic!("invalid worker")
            ),
            Err::<(), _>(Error::Header)
        );
        assert!(snapshot.bytes.iter().all(|byte| *byte == 0));
    }
    assert!(Request::new(&[0; CAPACITY + 1], 0x1000).is_err());
    assert!(Request::new(&[], 0).is_err());
    assert!(Request::new(&[], u64::MAX - 63).is_err());
    let empty = Request::new(&[], 0x1000).unwrap();
    assert_eq!(admit(empty.metadata()).unwrap().source, 0);
    assert_eq!(core::mem::size_of::<Request<'_>>(), HEADER);
}

fn oracle(input: &[u8], expected: &[u8; 32]) {
    let request = Request::new(input, 0x1000).unwrap();
    let mut snapshot = Snapshot::new();
    let mut workspace = Sha256Workspace::new();
    let mut output = [0xa5; 32];
    snapshot
        .with(
            request.metadata(),
            |_, bytes| {
                bytes.copy_from_slice(input);
                true
            },
            |bytes, _| {
                workspace.with(|mut state| {
                    for part in bytes.chunks(7) {
                        state.update(part).unwrap();
                    }
                    let secret = state.finalize_secret(&mut output).unwrap();
                    assert_eq!(secret.expose(), expected);
                });
            },
        )
        .unwrap();
    assert!(snapshot.bytes.iter().all(|byte| *byte == 0));
    assert_eq!(output, [0; 32]);
}

// The builder appends independent Python hashlib vectors and their test here.
