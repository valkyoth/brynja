//! Private Windows OS ABI; no imported cryptographic primitive implementation.
#![allow(unsafe_code)]
use super::super::Error;
use core::ffi::c_void;
type Handle = *mut c_void;

#[repr(C)]
struct CreateInfo {
    flags: u32,
    owner: [u8; 32],
}
#[repr(C)]
struct InitInfo {
    size: u32,
    threads: u32,
}
#[repr(C)]
#[derive(Default)]
struct SystemInfo {
    architecture: u32,
    page_size: u32,
    minimum: usize,
    maximum: usize,
    mask: usize,
    processors: u32,
    kind: u32,
    granularity: u32,
    level: u16,
    revision: u16,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct WorkingSet {
    address: usize,
    attributes: usize,
}
#[repr(C)]
struct Guid {
    a: u32,
    b: u16,
    c: u16,
    d: [u8; 8],
}
#[repr(C)]
struct TrustFile {
    size: u32,
    path: *const u16,
    file: Handle,
    subject: *const Guid,
}
#[repr(C)]
struct TrustData {
    size: u32,
    callback: Handle,
    sip: Handle,
    ui: u32,
    revocation: u32,
    choice: u32,
    file: *mut TrustFile,
    action: u32,
    state: Handle,
    url: *const u16,
    flags: u32,
    context: u32,
    settings: Handle,
}

#[link(name = "onecore")]
unsafe extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn GetCurrentThreadId() -> u32;
    fn IsWow64Process2(process: Handle, process_machine: *mut u16, native: *mut u16) -> i32;
    fn IsEnclaveTypeSupported(kind: u32) -> i32;
    fn GetSystemInfo(info: *mut SystemInfo);
    fn CreateEnclave(
        process: Handle,
        address: Handle,
        size: usize,
        initial: usize,
        kind: u32,
        info: *const CreateInfo,
        info_size: u32,
        error: *mut u32,
    ) -> Handle;
    fn LoadEnclaveImageW(base: Handle, image: *const u16) -> i32;
    fn InitializeEnclave(
        process: Handle,
        base: Handle,
        info: *mut InitInfo,
        size: u32,
        error: *mut u32,
    ) -> i32;
    fn TerminateEnclave(base: Handle, wait: i32) -> i32;
    fn DeleteEnclave(base: Handle) -> i32;
    fn GetLastError() -> u32;
    fn GetProcAddress(module: Handle, name: *const u8) -> Handle;
    fn CallEnclave(routine: Handle, parameter: Handle, wait: i32, result: *mut Handle) -> i32;
    fn VirtualLock(address: Handle, size: usize) -> i32;
    fn VirtualUnlock(address: Handle, size: usize) -> i32;
    fn CloseHandle(handle: Handle) -> i32;
    fn GetFileType(handle: Handle) -> u32;
}
#[link(name = "psapi")]
unsafe extern "system" {
    fn QueryWorkingSetEx(process: Handle, entries: *mut WorkingSet, size: u32) -> i32;
}
#[link(name = "wintrust")]
unsafe extern "system" {
    fn WinVerifyTrust(window: Handle, action: *const Guid, data: *mut TrustData) -> i32;
}

pub(super) fn supported() -> bool {
    let (mut process, mut native) = (0, 0);
    let mut info = SystemInfo::default();
    // SAFETY: fixed initialized ABI outputs; current process pseudo-handle.
    unsafe {
        GetSystemInfo(&mut info);
        IsWow64Process2(GetCurrentProcess(), &mut process, &mut native) != 0
            && process == 0
            && native == 0x8664
            && IsEnclaveTypeSupported(0x10) != 0
            && info.page_size == 4096
            && info.granularity == 65536
    }
}
pub(super) fn thread() -> u32 {
    // SAFETY: no pointers or caller resources.
    unsafe { GetCurrentThreadId() }
}
pub(super) fn create() -> Result<usize, Error> {
    let mut info = CreateInfo {
        flags: 0,
        owner: [0; 32],
    };
    if let Some(prefix) = info.owner.get_mut(..2) {
        prefix.copy_from_slice(b"BR");
    }
    // SAFETY: fixed ABI structure and validated native geometry; OS owns mapping.
    let base = unsafe {
        CreateEnclave(
            GetCurrentProcess(),
            core::ptr::null_mut(),
            0x10000000,
            0,
            0x10,
            &info,
            36,
            core::ptr::null_mut(),
        )
    };
    if base.is_null() {
        Err(Error::Platform)
    } else {
        Ok(base as usize)
    }
}
pub(super) fn load(base: usize, path: &[u16]) -> Result<(), Error> {
    if path.last() != Some(&0) {
        return Err(Error::Bounds);
    }
    // SAFETY: private live enclave mapping; bounded NUL-terminated pinned path.
    if unsafe { LoadEnclaveImageW(base as Handle, path.as_ptr()) } == 0 {
        Err(Error::Platform)
    } else {
        Ok(())
    }
}
pub(super) fn initialize(base: usize) -> Result<u32, Error> {
    let mut info = InitInfo {
        size: 8,
        threads: 1,
    };
    // SAFETY: private mapping loaded by OS, exclusive initialization, fixed output.
    if unsafe {
        InitializeEnclave(
            GetCurrentProcess(),
            base as Handle,
            &mut info,
            8,
            core::ptr::null_mut(),
        )
    } == 0
    {
        Err(Error::Platform)
    } else {
        Ok(info.threads)
    }
}
pub(super) fn export(base: usize, name: &'static [u8]) -> Result<usize, Error> {
    if name.last() != Some(&0) {
        return Err(Error::Protocol);
    }
    // SAFETY: initialized enclave and static terminated export name; no direct call.
    let address = unsafe { GetProcAddress(base as Handle, name.as_ptr()) };
    if address.is_null() || !super::protocol::inside(base, 0x10000000, address as usize, 1) {
        Err(Error::Platform)
    } else {
        Ok(address as usize)
    }
}
pub(super) fn call(routine: usize, parameter: usize) -> Result<usize, Error> {
    let mut result = core::ptr::null_mut();
    // SAFETY: private OS-resolved enclave routine. Caller keeps borrowed protocol
    // buffers live synchronously and revokes them before returning to application.
    if unsafe { CallEnclave(routine as Handle, parameter as Handle, 0, &mut result) } == 0 {
        Err(Error::Protocol)
    } else {
        Ok(result as usize)
    }
}
pub(super) fn destroy(base: usize, initialized: bool, terminated: &mut bool) -> Result<(), Error> {
    if initialized && !*terminated {
        // SAFETY: uniquely owned enclave with no active call or callback.
        if unsafe { TerminateEnclave(base as Handle, 0) } == 0 {
            return Err(Error::Release);
        }
        *terminated = true;
    }
    for _ in 0..100 {
        // SAFETY: private mapping, deletion only after confirmed termination.
        if unsafe { DeleteEnclave(base as Handle) } != 0 {
            return Ok(());
        }
        // SAFETY: thread-local error immediately after failed deletion.
        if unsafe { GetLastError() } != 814 {
            return Err(Error::Release);
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    Err(Error::Release)
}
pub(super) fn lock(address: usize, size: usize, acquire: bool) -> bool {
    // SAFETY: callback validates aligned enclave-owned disjoint ranges before
    // entry; this changes residency, never dereferences enclave data in Rust.
    unsafe {
        if acquire {
            VirtualLock(address as Handle, size) != 0
        } else {
            VirtualUnlock(address as Handle, size) != 0
        }
    }
}
pub(super) fn pages(address: usize, count: usize, locked: bool) -> bool {
    if count != 1 && count != 16 {
        return false;
    }
    let mut entries = [WorkingSet::default(); 16];
    for (i, entry) in entries.iter_mut().take(count).enumerate() {
        let Some(offset) = i.checked_mul(4096).and_then(|o| address.checked_add(o)) else {
            return false;
        };
        entry.address = offset;
    }
    let Ok(size) = u32::try_from(count.saturating_mul(16)) else {
        return false;
    };
    // SAFETY: bounded initialized array, OS writes only count entries.
    if unsafe { QueryWorkingSetEx(GetCurrentProcess(), entries.as_mut_ptr(), size) } == 0 {
        return false;
    }
    entries.iter().take(count).all(|e| {
        let observed = e.attributes & 1 == 1 && (e.attributes >> 22) & 1 != 0;
        if locked { observed } else { !observed }
    })
}
pub(super) fn close(handle: std::os::windows::io::RawHandle) {
    // SAFETY: ownership was transferred from File with into_raw_handle exactly
    // once. A failed close cannot be reported as confirmed guard release.
    if unsafe { CloseHandle(handle) } == 0 {
        std::process::abort();
    }
}
pub(super) fn disk(handle: std::os::windows::io::RawHandle) -> bool {
    // SAFETY: borrowed live File handle, never closed by this query.
    unsafe { GetFileType(handle) == 1 }
}
pub(super) fn signature(
    path: &[u16],
    handle: std::os::windows::io::RawHandle,
) -> Result<(), Error> {
    if path.last() != Some(&0) {
        return Err(Error::Bounds);
    }
    let action = Guid {
        a: 0x00aac56b,
        b: 0xcd44,
        c: 0x11d0,
        d: [0x8c, 0xc2, 0, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
    };
    let mut file = TrustFile {
        size: 32,
        path: path.as_ptr(),
        file: handle,
        subject: core::ptr::null(),
    };
    let mut trust = TrustData {
        size: 88,
        callback: core::ptr::null_mut(),
        sip: core::ptr::null_mut(),
        ui: 2,
        revocation: 1,
        choice: 1,
        file: &mut file,
        action: 1,
        state: core::ptr::null_mut(),
        url: core::ptr::null(),
        flags: 0x2080,
        context: 0,
        settings: core::ptr::null_mut(),
    };
    // SAFETY: fixed SDK layouts, pinned live file/path, no callbacks. CLOSE is
    // mandatory even when verification fails, and its failure also rejects.
    let (verified, closed) = unsafe {
        let verified = WinVerifyTrust(usize::MAX as Handle, &action, &mut trust);
        trust.action = 2;
        (
            verified,
            WinVerifyTrust(usize::MAX as Handle, &action, &mut trust),
        )
    };
    if closed != 0 {
        std::process::abort();
    }
    if verified == 0 {
        Ok(())
    } else {
        Err(Error::Signature)
    }
}

const _: () = {
    assert!(core::mem::size_of::<SystemInfo>() == 48);
    assert!(core::mem::size_of::<CreateInfo>() == 36);
    assert!(core::mem::size_of::<TrustFile>() == 32);
    assert!(core::mem::size_of::<TrustData>() == 88);
};
