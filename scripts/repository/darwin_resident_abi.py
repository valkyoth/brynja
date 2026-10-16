"""Exact Darwin resident-profile OS ABI and reviewed source boundaries."""
from pathlib import Path

UNSAFE_MODULES = {
    Path("crates/brynja-crypto-cpu-std/src/macos_resident/resource/darwin.rs"): ("4368b9459e3b70ccf6d10e7a032e19a02351759d06774b2309794d3702b49cb2", 10, 0, 10),
    Path("crates/brynja-crypto-cpu-std/src/macos_resident/resource/darwin/thread.rs"): ("64320b68afef88dfec1d1e267b563a3b93bca030050a14bc2b5042c95169adbf", 6, 0, 6),
    Path("crates/brynja-crypto-cpu-std/src/macos_resident/resource/darwin/observe.rs"): ("31636114ce7f2450732513ff778c0f739ccb9df778928e68a8bf84bba0e1efb1", 3, 0, 3),
}

OS_ABIS = {
    Path("crates/brynja-crypto-cpu-std/src/macos_resident/resource/darwin.rs"): (
        '''unsafe extern "C" {
    safe fn getpagesize() -> i32;
    static mach_task_self_: u32;
    fn mmap(
        addr: *mut c_void,
        len: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> *mut c_void;
    fn mach_vm_inherit(task: u32, address: u64, size: u64, inheritance: i32) -> i32;
    fn mprotect(addr: *mut c_void, len: usize, prot: i32) -> i32;
    fn mlock(addr: *const c_void, len: usize) -> i32;
    fn munmap(addr: *mut c_void, len: usize) -> i32;
}''',
    ),
    Path("crates/brynja-crypto-cpu-std/src/macos_resident/resource/darwin/thread.rs"): (
        '''unsafe extern "C" {
    fn pthread_attr_init(attr: *mut Attr) -> i32;
    fn pthread_attr_destroy(attr: *mut Attr) -> i32;
    fn pthread_attr_setstack(attr: *mut Attr, address: *mut c_void, bytes: usize) -> i32;
    fn pthread_create(
        thread: *mut *mut c_void,
        attr: *const Attr,
        start: extern "C" fn(*mut c_void) -> *mut c_void,
        arg: *mut c_void,
    ) -> i32;
    fn pthread_join(thread: *mut c_void, result: *mut *mut c_void) -> i32;
}''',
        '''extern "C" fn enter<F: FnOnce() + Send>(argument: *mut c_void) -> *mut c_void {''',
    ),
    Path("crates/brynja-crypto-cpu-std/src/macos_resident/resource/darwin/observe.rs"): (
        '''unsafe extern "C" {
    fn mach_vm_region(
        task: u32,
        address: *mut u64,
        size: *mut u64,
        flavor: i32,
        info: *mut i32,
        count: *mut u32,
        object: *mut u32,
    ) -> i32;
    fn mach_port_deallocate(task: u32, name: u32) -> i32;
    fn mach_vm_read_overwrite(
        task: u32,
        source: u64,
        size: u64,
        destination: u64,
        actual: *mut u64,
    ) -> i32;
}''',
    ),
}

