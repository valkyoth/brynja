"""Exact Darwin resident-profile OS ABI and reviewed source boundaries."""
from pathlib import Path

UNSAFE_MODULES = {
    Path("crates/brynja-crypto-cpu-std/src/macos_resident/resource/darwin.rs"): ("a32e1624f4e8bdcc4b129db19e26af37ae88096fb417caeeaac51c8d2aaa8d04", 10, 0, 10),
    Path("crates/brynja-crypto-cpu-std/src/macos_resident/resource/darwin/thread.rs"): ("0a5d3e71e6938fa0a46e10b486e58e1f6b61229a4496bef1238c4b37a2d87a59", 6, 0, 6),
    Path("crates/brynja-crypto-cpu-std/src/macos_resident/resource/darwin/observe.rs"): ("31636114ce7f2450732513ff778c0f739ccb9df778928e68a8bf84bba0e1efb1", 3, 0, 3),
}

OS_ABIS = {
    Path("crates/brynja-crypto-cpu-std/src/macos_resident/resource/darwin.rs"): (
        '''unsafe extern "C" {
    safe fn getpid() -> i32;
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

# Rust has no cross-crate private visibility. Keep legacy workers private rather
# than export a callback API or introduce legacy dependencies into modern crates.
# These copies must remain byte-identical to the reviewed OS-only implementation.
PRIVATE_COPIES = {}
for family in ('sha1', 'md5', 'parallel'):
    destination = Path(f'crates/brynja-legacy-{family}-std/src/macos_resident') if family != 'parallel' else Path('crates/brynja-hash-parallel-std/src/macos_resident')
    origin = Path('crates/brynja-crypto-cpu-std/src/macos_resident')
    for relative in ('resource.rs', 'resource/darwin.rs', 'resource/darwin/thread.rs',
                     'resource/darwin/observe.rs', 'resource/darwin/tests.rs'):
        PRIVATE_COPIES[destination / relative] = origin / relative
        if origin / relative in UNSAFE_MODULES:
            UNSAFE_MODULES[destination / relative] = UNSAFE_MODULES[origin / relative]
            OS_ABIS[destination / relative] = OS_ABIS[origin / relative]


# Only ParallelHash adds scoped groups; canonical single-worker code stays exact.
PARALLEL_ADDITIONS = {
    "resource.rs": ("        pub(in super::super) fn run<", "        pub(in super::super) fn run_group<F: FnMut() + Send>(\n            _: &mut [Self],\n            _: &mut [F],\n        ) -> Result<(), Error> {\n            Err(Error::Unsupported)\n        }\n"),
    "resource/darwin.rs": ("    #[cfg(test)]\n    pub(in super::super) fn verify_native", "    pub(in super::super) fn run_group<F: FnMut() + Send>(\n        mappings: &mut [Self],\n        work: &mut [F],\n    ) -> Result<(), Error> {\n        thread::run_group(mappings, work)\n    }\n"),
    "resource/darwin/thread.rs": ("// Darwin _opaque", "mod group;\npub(super) use group::run as run_group;\n\n"),
}
UNSAFE_MODULES[Path("crates/brynja-hash-parallel-std/src/macos_resident/resource/darwin.rs")] = ("204ccb1cc473e4fa5979c2cb84157ad7f8c375474a6af5a6abef9672ce622171", 10, 0, 10)
UNSAFE_MODULES[Path("crates/brynja-hash-parallel-std/src/macos_resident/resource/darwin/thread.rs")] = ("deb11bb14add57d5ad39875c403486e513a2f8d79d857b074703ce52f06dc7f6", 6, 0, 6)
UNSAFE_MODULES[Path("crates/brynja-hash-parallel-std/src/macos_resident/resource/darwin/thread/group.rs")] = ("c311fb76f05bc79fa47fd89f2c499b39e0172b9c6b96fcf6bb40cccaedfe1f39", 3, 0, 3)

def validate_private_copies(root):
    for copy, original in PRIVATE_COPIES.items():
        expected = (root / original).read_text()
        if copy.name == 'resource.rs':
            expected = expected.replace('use super::Error;', 'use super::ResourceError as Error;', 1)
        if copy.parts[1] == 'brynja-hash-parallel-std':
            relative = copy.relative_to(Path('crates/brynja-hash-parallel-std/src/macos_resident')).as_posix()
            if relative in PARALLEL_ADDITIONS:
                anchor, addition = PARALLEL_ADDITIONS[relative]
                if expected.count(anchor) != 1:
                    raise ValueError('private Darwin group anchor drift')
                expected = expected.replace(anchor, addition + anchor, 1)
        if (root / copy).is_symlink() or (root / copy).read_text() != expected:
            raise ValueError('private Darwin adapter diverged: ' + str(copy))

