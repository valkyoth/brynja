// Appended only to an isolated test copy of the native concurrent module.
#![allow(unsafe_code)]
use super::*;
#[repr(C)]
#[derive(Default)]
struct MemoryInfo {
    base: usize, allocation: usize, allocation_protect: u32, partition: u16,
    size: usize, state: u32, protect: u32, kind: u32,
}
#[link(name = "onecore")]
unsafe extern "system" {
    fn VirtualQuery(address: *const core::ffi::c_void, out: *mut MemoryInfo, size: usize) -> usize;
}
pub(super) fn freed(base: usize) {
    assert_ne!(base, 0);
    assert_eq!(core::mem::size_of::<MemoryInfo>(), 48);
    let mut info = MemoryInfo::default();
    assert_eq!(unsafe { VirtualQuery(base as *const _, &mut info, 48) }, 48);
    assert_eq!(info.state, 0x10000, "concurrent enclave mapping retained");
}
pub(super) fn pin_released() {
    let path = std::env::var_os("BRYNJA_PARALLEL_CONCURRENT_IMAGE").unwrap();
    assert!(std::fs::OpenOptions::new().write(true).open(path).is_ok(), "concurrent image pin retained");
}
fn open() -> Transport {
    let path = std::env::var_os("BRYNJA_PARALLEL_CONCURRENT_IMAGE").unwrap();
    let text = std::env::var("BRYNJA_PARALLEL_CONCURRENT_SHA256").unwrap();
    assert_eq!(text.len(), 64);
    let mut digest = [0; 32];
    for (out, pair) in digest.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *out = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    let mut family = [0; 16];
    let mut image = [0; 16];
    family[..4].copy_from_slice(b"BRYN");
    image[..4].copy_from_slice(b"PAWV");
    Transport::development(Path::new(&path), &ImagePolicy::reviewed_sha256(
        digest, family, image, 1, 1, [0, 0])).unwrap()
}
#[test]
fn unopened_drop_and_entry_unwind() {
    let owner = open();
    let base = owner.base;
    drop(owner);
    freed(base);
    pin_released();
    println!("CONCURRENT_TEARDOWN: unopened-drop; mapping=free; pin=released");
    let mut owner = open();
    let base = owner.base;
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        owner.used = true;
        let _entry = Entry(&mut owner);
        panic!("synthetic host unwind; no active enclave call");
    }));
    assert!(caught.is_err());
    freed(base);
    assert!(owner.used && owner.test_closed());
    pin_released();
    println!("CONCURRENT_TEARDOWN: entry-unwind; mapping=free; pin=released");
}
