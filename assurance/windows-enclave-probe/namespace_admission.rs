// Appended inside the shipping namespace module in a temporary native fixture.
// OS entropy is replaced only in this fixture, never in the published library.
use core::sync::atomic::{AtomicU32, Ordering};
static CALLS: AtomicU32 = AtomicU32::new(0);
fn entropy(algorithm: Handle, buffer: *mut u8, size: u32, flags: u32) -> i32 {
    assert!(algorithm.is_null());
    assert_eq!((size, flags), (16, 2));
    let call = CALLS.fetch_add(1, Ordering::SeqCst);
    let mode = std::env::args().nth(1).unwrap();
    if mode == "entropy-failure" { return -1; }
    let value = if mode == "retry" { u8::try_from(call + 1).unwrap() } else { 1 };
    unsafe { core::ptr::write_bytes(buffer, value, 16); }
    0
}
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtOpenSymbolicLinkObject(out: *mut Handle, access: u32, attributes: *const Attributes) -> i32;
}
fn attributes(name: &Unicode, flags: u32) -> Attributes {
    Attributes { length: 48, root: core::ptr::null_mut(), name, flags,
                 security: core::ptr::null(), quality: core::ptr::null() }
}
fn alias(nonce: u8) -> Vec<u16> {
    format!(r"\??\BrynjaImage-{}.dll", format!("{nonce:02x}").repeat(16)).encode_utf16().collect()
}
fn preclaim() -> ImageName {
    let name = alias(1);
    let name = unicode(&name).unwrap();
    let target: Vec<_> = r"\Device\HarddiskVolume1".encode_utf16().collect();
    let target = unicode(&target).unwrap();
    let mut handle = core::ptr::null_mut();
    assert_eq!(unsafe { NtCreateSymbolicLinkObject(&mut handle, 1, &attributes(&name, 0x40), &target) }, 0);
    assert!(!handle.is_null());
    ImageName { handle, location: Vec::new() }
}
fn open_status(name: &[u16]) -> i32 {
    let name = unicode(name).unwrap();
    let mut handle = core::ptr::null_mut();
    let status = unsafe { NtOpenSymbolicLinkObject(&mut handle, 1, &attributes(&name, 0x40)) };
    if status == 0 { assert!(!handle.is_null()); sys::close(handle); }
    else { assert!(handle.is_null()); }
    status
}
fn child(nonce: u8, expected: &str) {
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["child", &nonce.to_string(), expected]).output().unwrap();
    assert!(result.status.success(), "sibling open check failed: {}", String::from_utf8_lossy(&result.stderr));
    assert!(String::from_utf8_lossy(&result.stdout).contains("SIBLING_OPEN: PASS"));
}
pub(crate) fn probe() {
    let mode = std::env::args().nth(1).unwrap();
    if mode == "child" {
        let nonce: u8 = std::env::args().nth(2).unwrap().parse().unwrap();
        let status = open_status(&alias(nonce)) as u32;
        if std::env::args().nth(3).unwrap() == "allowed" { assert_eq!(status, 0); }
        else { assert!(matches!(status, 0xc0000022 | 0xc0000043), "unexpected status {status:08x}"); }
        println!("SIBLING_OPEN: PASS");
        return;
    }
    let target: Vec<_> = r"\\?\GLOBALROOT\Device\HarddiskVolume1".encode_utf16().collect();
    if mode == "entropy-failure" {
        assert!(matches!(ImageName::create(&target), Err(Error::Platform)), "entropy failure did not reject before creating alias");
        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(open_status(&alias(1)) as u32, 0xc0000034);
    } else {
        let preexisting = preclaim();
        child(1, "allowed"); // proves same logon map and permission, not an absent-name pass
        let owner = ImageName::create(&target);
        if mode == "retry" {
            let owner = owner.expect("collision retry did not create fresh alias");
            assert_eq!(CALLS.load(Ordering::SeqCst), 2);
            assert!(String::from_utf16(owner.location()).unwrap().contains(&"02".repeat(16)));
            child(2, "denied");
            drop(owner);
            assert_eq!(open_status(&alias(2)) as u32, 0xc0000034, "alias retained after Drop");
        } else {
            assert_eq!(mode, "exhausted");
            assert!(matches!(owner, Err(Error::Image)));
            assert_eq!(CALLS.load(Ordering::SeqCst), 4, "collision attempts not bounded");
        }
        child(1, "allowed"); // rejection/retry did not close or replace the original
        drop(preexisting);
        assert_eq!(open_status(&alias(1)) as u32, 0xc0000034);
    }
    println!("NAMESPACE_ADMISSION: {mode}: PASS");
}
