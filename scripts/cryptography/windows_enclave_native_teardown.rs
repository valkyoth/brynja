// Test-only child of the shipping lifecycle module in an isolated source copy.
// No OS mocks or production constructor changes, and no erasure claim.
#![allow(unsafe_code)]
use super::super::super::kmac_wire::Request;
use super::super::{ImagePolicy, Protocol};
use super::*;
use std::path::PathBuf;

#[repr(C)]
#[derive(Default)]
struct MemoryInfo {
    base: usize,
    allocation: usize,
    allocation_protect: u32,
    partition: u16,
    size: usize,
    state: u32,
    protect: u32,
    kind: u32,
}
#[link(name = "onecore")]
unsafe extern "system" {
    fn VirtualQuery(address: *const core::ffi::c_void, info: *mut MemoryInfo, size: usize)
    -> usize;
}
fn memory(address: usize) -> MemoryInfo {
    assert_eq!(core::mem::size_of::<MemoryInfo>(), 48);
    let mut info = MemoryInfo::default();
    // SAFETY: a fixed initialized x64 ABI output; the OS queries the numeric
    // address without dereferencing enclave data in this test or Rust code.
    let count = unsafe {
        VirtualQuery(
            address as *const _,
            &mut info,
            core::mem::size_of::<MemoryInfo>(),
        )
    };
    assert_eq!(count, 48);
    info
}
fn freed(base: usize, slot: usize) {
    // Query immediately before doing allocations or opening the image again.
    // MEM_FREE establishes unmapping, not physical-page scrubbing.
    assert_eq!(memory(base).state, 0x10000, "enclave mapping retained");
    assert_eq!(memory(slot).state, 0x10000, "owner page retained");
}
fn image() -> (PathBuf, ImagePolicy) {
    let path = PathBuf::from(std::env::var_os("BRYNJA_TEARDOWN_IMAGE").unwrap());
    let expected = std::env::var("BRYNJA_TEARDOWN_SHA256").unwrap();
    assert_eq!(expected.len(), 64);
    let mut digest = [0; 32];
    for (out, pair) in digest.iter_mut().zip(expected.as_bytes().chunks_exact(2)) {
        *out = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    let mut family = [0; 16];
    let mut id = [0; 16];
    family[..4].copy_from_slice(b"BRYN");
    id[..4].copy_from_slice(b"PROB");
    (
        path,
        ImagePolicy::reviewed_sha256(digest, family, id, 1, 1, [0, 0]),
    )
}
fn request(owner: &mut Backend, request: Request, input: &[u8]) {
    let header = request.header(input).unwrap();
    assert_eq!(
        owner.run_kmac(request.op, Some(&header), input.len(), None),
        Ok(()),
        "setup operation {} sequence {}",
        request.op,
        request.sequence
    );
}
fn keyed_owner(path: &std::path::Path, policy: &ImagePolicy) -> Backend {
    let mut owner = Backend::open_protocol(
        path,
        policy,
        |pin| {
            // Development signature rejection is mandatory. This test-only closure
            // cannot be selected by a production application or Cargo feature.
            assert_eq!(pin.signature(), Err(Error::Signature));
            Ok(())
        },
        Protocol::Kmac,
    )
    .unwrap();
    owner.live = true;
    owner.run_kmac(0, None, 0, None).unwrap();
    request(
        &mut owner,
        Request {
            op: 40,
            sequence: 1,
            algorithm: 1,
            key_bits: 128,
            ..Request::default()
        },
        &[],
    );
    request(
        &mut owner,
        Request {
            op: 42,
            sequence: 2,
            ..Request::default()
        },
        &[],
    );
    request(
        &mut owner,
        Request {
            op: 43,
            sequence: 3,
            last: 8,
            ..Request::default()
        },
        &[0x37; 16],
    );
    request(
        &mut owner,
        Request {
            op: 44,
            sequence: 4,
            ..Request::default()
        },
        &[],
    );
    request(
        &mut owner,
        Request {
            op: 45,
            sequence: 5,
            last: 8,
            ..Request::default()
        },
        &[0x59; 32],
    );
    assert!(owner.initialized && owner.live && owner.slot_locked && !owner.uncertain);
    assert!(!owner.registrations_pending.get());
    assert_eq!(memory(owner.base).allocation, owner.base);
    assert_eq!(memory(owner.slot).allocation, owner.base);
    assert!(sys::pages(owner.slot, 1, true));
    assert!(std::fs::OpenOptions::new().write(true).open(path).is_err());
    owner
}

#[test]
fn real_post_failure_teardown() {
    let (path, policy) = image();
    for failure in [
        "normal",
        "bad-version",
        "bad-sequence",
        "bad-receipt",
        "unwind",
    ] {
        for explicit in [false, true] {
            let mut owner = keyed_owner(&path, &policy);
            let base = owner.base;
            let slot = owner.slot;
            if failure != "normal" {
                if failure == "unwind" {
                    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        // Real registration exports; no active CallEnclave when
                        // unwinding. Pointers remain borrowed through revocation.
                        let header = [0u8; 96];
                        let mut output = [0u8; 1];
                        let guard = Registration::new(&owner.entries, &owner.registrations_pending);
                        owner.uncertain = true;
                        assert_eq!(
                            sys::call(owner.entries.input, header.as_ptr() as usize),
                            Ok(1)
                        );
                        assert_eq!(
                            sys::call(owner.entries.output, output.as_mut_ptr() as usize),
                            Ok(1)
                        );
                        let _guard = guard;
                        panic!("synthetic recoverable host unwind");
                    }));
                    assert!(caught.is_err());
                } else {
                    let mut header = Request {
                        op: 45,
                        sequence: 6,
                        ..Request::default()
                    }
                    .header(&[])
                    .unwrap();
                    if failure == "bad-version" {
                        header[0] ^= 1;
                    }
                    if failure == "bad-sequence" {
                        header[8] = 2;
                    }
                    if failure == "bad-receipt" {
                        // Redirect a public receipt query to a different real
                        // export. The operation executes but inspection fails.
                        owner.entries.sha2_control = owner.entries.window;
                    }
                    assert!(owner.run_kmac(45, Some(&header), 0, None).is_err());
                }
                assert!(owner.uncertain);
                assert!(!owner.registrations_pending.get());
                assert_eq!(owner.run_kmac(0, None, 0, None), Err(Error::Quarantined));
                assert_eq!(owner.close(), Err(Error::Release));
                assert_ne!(memory(base).state, 0x10000);
            }
            if explicit {
                if failure == "normal" {
                    owner.close().unwrap();
                } else {
                    owner.destroy_quarantined().unwrap();
                    assert!(owner.uncertain, "destruction must not clear quarantine");
                    assert!(!owner.live && !owner.slot_locked && owner.pin.is_none());
                }
                assert_eq!(owner.base, 0);
            }
            drop(owner);
            freed(base, slot);
            assert!(std::fs::OpenOptions::new().write(true).open(&path).is_ok());
            println!("NATIVE_TEARDOWN: {failure}; explicit={explicit}; mapping=free; pin=released");
        }
    }
    // A new keyed instance must still be usable after all failure cases.
    let mut recovered = keyed_owner(&path, &policy);
    recovered.close().unwrap();
    println!("NATIVE_TEARDOWN: fresh-owner=PASS; cases=10; erasure=NOT_PROVEN");
}
