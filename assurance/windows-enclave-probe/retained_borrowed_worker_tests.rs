extern crate std;
use super::*;
use core::mem::MaybeUninit;
use persistent_result::{Error, PUBLIC_OUTPUT};
use std::panic::{AssertUnwindSafe, catch_unwind};
#[repr(align(4096))]
struct Page([MaybeUninit<u8>; 4096]);
struct Mock<'a> {
    header: [u8; 32],
    input: &'a [u8],
    reads: [usize; 2],
    fail: Option<usize>,
    unwind: bool,
}
impl<'a> Mock<'a> {
    fn new(input: &'a [u8]) -> Self {
        let mut header = [0; 32];
        for (word, out) in [
            4u64,
            11,
            input.len() as u64,
            if input.is_empty() { 0 } else { 5678 },
        ]
        .into_iter()
        .zip(header.chunks_exact_mut(8))
        {
            out.copy_from_slice(&word.to_le_bytes());
        }
        Self {
            header,
            input,
            reads: [0; 2],
            fail: None,
            unwind: false,
        }
    }
}
impl CopyInput for Mock<'_> {
    fn read(&mut self, kind: usize, address: usize, bytes: &mut [u8]) -> bool {
        assert!(kind < 2);
        self.reads[kind] += 1;
        assert_eq!(address, if kind == 0 { 1234 } else { 5678 });
        if self.fail == Some(kind) {
            let partial = bytes.len().min(17);
            bytes[..partial].fill(0xa5);
            if self.unwind {
                panic!("copy seam unwind");
            }
            return false;
        }
        if kind == 0 {
            bytes.copy_from_slice(&self.header);
            self.header.fill(0xff);
        } else {
            bytes.copy_from_slice(self.input);
        }
        true
    }
}
fn buffers() -> Buffers {
    Buffers {
        header: [0; 32],
        snapshot: [0; 1024],
        staging: [0; 32],
    }
}
fn clean(b: &Buffers, w: &Sha256Workspace) {
    assert!(zero(&b.header) && zero(&b.snapshot) && zero(&b.staging) && workspace_zero(w));
}
fn oracle(input: &[u8], digest: &[u8; 32]) {
    let mut page = Page([MaybeUninit::new(0); 4096]);
    let mut owner = Placed::new(&mut page.0, [7, 9]).unwrap();
    let token = {
        let mut b = buffers();
        let mut w = Sha256Workspace::new();
        let mut io = Mock::new(input);
        let (status, length, token) = receive(&mut owner, &mut w, &mut b, 1234, 11, &mut io);
        assert_eq!(status, 2);
        assert_eq!(length, input.len());
        assert_eq!(io.reads, [1, usize::from(!input.is_empty())]);
        clean(&b, &w);
        token.unwrap()
    };
    let mut output = [0; 32];
    owner
        .export_public(token, PUBLIC_OUTPUT, |bytes| {
            output.copy_from_slice(bytes);
            true
        })
        .unwrap();
    assert_eq!(output, *digest);
}
#[test]
fn invalid_sequence_never_reaches_payload_copy() {
    let mut page = Page([MaybeUninit::new(0); 4096]);
    let mut owner = Placed::new(&mut page.0, [7, 9]).unwrap();
    let mut io = Mock::new(b"abc");
    io.header[8..16].copy_from_slice(&12u64.to_le_bytes());
    let mut b = buffers();
    let mut w = Sha256Workspace::new();
    assert_eq!(
        receive(&mut owner, &mut w, &mut b, 1234, 11, &mut io),
        (120, 0, None)
    );
    assert_eq!(io.reads, [1, 0]);
    clean(&b, &w);
    assert_eq!(
        owner.hash(&mut w, &mut b.staging, b"reuse"),
        Err(Error::Quarantined)
    );
}
#[test]
fn partial_header_and_payload_failure_or_unwind_clear_and_quarantine() {
    for kind in [0, 1] {
        for unwind in [false, true] {
            let mut page = Page([MaybeUninit::new(0); 4096]);
            let mut owner = Placed::new(&mut page.0, [7, 9]).unwrap();
            let mut io = Mock::new(b"public native input fixture");
            io.fail = Some(kind);
            io.unwind = unwind;
            let mut b = buffers();
            let mut w = Sha256Workspace::new();
            let result = catch_unwind(AssertUnwindSafe(|| {
                receive(&mut owner, &mut w, &mut b, 1234, 11, &mut io)
            }));
            assert_eq!(result.is_err(), unwind);
            if let Ok((status, _, token)) = result {
                assert_eq!(status, 121);
                assert_eq!(token, None);
            }
            assert_eq!(io.reads, [1, kind]);
            clean(&b, &w);
            assert_eq!(
                owner.hash(&mut w, &mut b.staging, b"reuse"),
                Err(Error::Quarantined)
            );
        }
    }
}
#[unsafe(no_mangle)]
extern "C" fn PublicInputSource() -> usize {
    0
}
#[unsafe(no_mangle)]
extern "C" fn PublicInputCopy(_: usize, _: *mut u8, _: usize, _: usize) -> i32 {
    -1
}
#[unsafe(no_mangle)]
extern "C" fn PublicInputObserve(_: *const usize) -> i32 {
    0
}
#[unsafe(no_mangle)]
extern "C" fn PublicRetainedCopy(_: usize, _: *const u8, _: usize) -> i32 {
    -1
}
