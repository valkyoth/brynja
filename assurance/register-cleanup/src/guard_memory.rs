//! Shared Linux guard-page backing for opaque-kernel tests.
extern crate std;
use core::ffi::{c_int, c_void};
use std::io;

unsafe extern "C" {
    fn getpagesize() -> c_int;
    fn mmap(
        address: *mut c_void,
        length: usize,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: i64,
    ) -> *mut c_void;
    fn mprotect(address: *mut c_void, length: usize, prot: c_int) -> c_int;
    fn munmap(address: *mut c_void, length: usize) -> c_int;
}

pub(crate) struct Pages {
    base: *mut u8,
    page: usize,
    length: usize,
    writable: bool,
}

impl Pages {
    pub(crate) fn new() -> io::Result<Self> {
        // SAFETY: Linux libc query takes no pointers or mutable state.
        let size = unsafe { getpagesize() };
        let page = usize::try_from(size).map_err(io::Error::other)?;
        if page < 704 {
            return Err(io::Error::other("page too short for fixed kernel regions"));
        }
        let length = page
            .checked_mul(3)
            .ok_or_else(|| io::Error::other("page count overflow"))?;
        // SAFETY: Request a private anonymous, inaccessible three-page mapping.
        // Linux MAP_PRIVATE=2, MAP_ANONYMOUS=32, PROT_NONE=0; no file descriptor.
        let pointer = unsafe { mmap(core::ptr::null_mut(), length, 0, 2 | 32, -1, 0) };
        if pointer as isize == -1 {
            return Err(io::Error::last_os_error());
        }
        let pages = Self {
            base: pointer.cast(),
            page,
            length,
            writable: true,
        };
        if pages.base.is_null() {
            return Err(io::Error::other("null mapping cannot back Rust references"));
        }
        // SAFETY: The middle whole page lies within this exact live mapping.
        // Linux PROT_READ|PROT_WRITE=3. Surrounding pages stay inaccessible.
        if unsafe { mprotect(pages.base.add(page).cast(), page, 3) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(pages)
    }

    pub(crate) fn bytes<const N: usize>(&mut self, at_end: bool) -> &mut [u8; N] {
        assert!(
            self.writable,
            "cannot create a mutable borrow of a read-only page"
        );
        assert!(N <= self.page);
        let offset = if at_end { self.page - N } else { 0 };
        // SAFETY: The checked N-byte range lies wholly in the initialized,
        // writable middle page. The exclusive self borrow prevents aliasing.
        unsafe { &mut *self.base.add(self.page + offset).cast::<[u8; N]>() }
    }

    pub(crate) fn readonly(&mut self) -> io::Result<()> {
        // SAFETY: No borrow escapes this method. This live middle page changes
        // to PROT_READ=1 before any shared reference is passed to the kernel.
        if unsafe { mprotect(self.base.add(self.page).cast(), self.page, 1) } != 0 {
            return Err(io::Error::last_os_error());
        }
        self.writable = false;
        Ok(())
    }

    pub(crate) fn read<const N: usize>(&self, at_end: bool) -> &[u8; N] {
        assert!(N <= self.page);
        let offset = if at_end { self.page - N } else { 0 };
        // SAFETY: The exact checked range is initialized and readable; shared
        // borrowing cannot mutate it. The mapping stays live until Drop.
        unsafe { &*self.base.add(self.page + offset).cast::<[u8; N]>() }
    }
}

impl Drop for Pages {
    fn drop(&mut self) {
        // SAFETY: This object uniquely owns this entire exact mmap allocation.
        let result = unsafe { munmap(self.base.cast(), self.length) };
        assert_eq!(result, 0, "guard-page mapping could not be released");
    }
}
