//! Isolated Linux GNU 64-bit mapping adapter; no foreign cryptography.
//!
//! Constants/signatures match Linux UAPI and the GNU libc mmap ABI on the two
//! cfg-selected targets. No allocator, caller mapping or active stack is owned
//! here. The owner always unmaps the entire dedicated mapping, never a subrange.
#![allow(unsafe_code)]

use super::{Error, geometry::Layout};
use core::{ffi::c_void, ptr::NonNull};

mod sys;
#[cfg(test)]
mod tests;

pub(super) struct Mapping {
    base: Option<NonNull<u8>>,
    data: NonNull<u8>,
    layout: Layout,
    used: usize,
    admitted: bool,
}

impl Mapping {
    pub(super) fn new(bytes: usize, max: usize) -> Result<Self, Error> {
        let page = usize::try_from(sys::page_size()).map_err(|_| Error::InvalidSize)?;
        let layout = Layout::new(bytes, max, page)?;
        let base = sys::map(layout.total)?;
        // SAFETY: map owns a fresh layout.total-byte mapping; layout.page is
        // smaller than total and points to the first byte after the lower guard.
        let data = unsafe { NonNull::new_unchecked(base.as_ptr().add(layout.page)) };
        let mut mapping = Self {
            base: Some(base),
            data,
            layout,
            used: bytes,
            admitted: false,
        };
        // Exclude the complete mapping before making any payload accessible.
        sys::advise(base, layout.total, sys::DONTDUMP, Error::DumpExclusion)?;
        sys::advise(base, layout.total, sys::DONTFORK, Error::ForkExclusion)?;
        sys::access(data, layout.payload)?;
        sys::lock(data, layout.payload)?;
        mapping.admitted = true;
        Ok(mapping)
    }

    pub(super) fn bytes(&self) -> &[u8] {
        // SAFETY: externally usable mappings completed protection acquisition;
        // immutable borrowing excludes mutable access and close/drop. Anonymous
        // pages are initialized to zero, used <= payload <= isize::MAX.
        unsafe { core::slice::from_raw_parts(self.data.as_ptr(), self.used) }
    }

    pub(super) fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: the exclusive owner borrow covers the initialized, live
        // mapping; guards/padding are outside the returned used-byte subrange.
        unsafe { core::slice::from_raw_parts_mut(self.data.as_ptr(), self.used) }
    }

    pub(super) fn clear(&mut self) {
        // Failed construction has never admitted secret bytes. Do not fault
        // in a potentially huge zero-only mapping after residency acquisition
        // fails: rollback can unmap it directly, without an unbounded wipe.
        if self.base.is_none() || !self.admitted {
            return;
        }
        // SAFETY: this exclusively owned full payload is live and read/write.
        // Inaccessible guard pages are not included. No loans can outlive &mut.
        let region =
            unsafe { core::slice::from_raw_parts_mut(self.data.as_ptr(), self.layout.payload) };
        // Layout forbids empty payloads. This primitive performs volatile stores.
        let _ = brynja_core::clear_owned_region(region);
        #[cfg(test)]
        sys::observe_clear(region.iter().all(|byte| *byte == 0));
    }

    pub(super) fn close(&mut self) -> Result<(), Error> {
        let Some(base) = self.base else {
            return Ok(());
        };
        self.clear();
        // munmap itself releases the locks. There is no unlocked live interval.
        sys::unmap(base, self.layout.total)?;
        self.base = None;
        self.admitted = false;
        self.used = 0;
        Ok(())
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // Failure leaves a cleared mapping resident; never free an active loan.
        // Rust safety is independent of whether the OS releases these resources.
        let _ = self.close();
    }
}

// The FFI symbols are restricted by the first-party OS-adapter inventory.
unsafe extern "C" {
    safe fn getpagesize() -> i32;
    fn mmap(
        addr: *mut c_void,
        len: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> *mut c_void;
    fn mprotect(addr: *mut c_void, len: usize, prot: i32) -> i32;
    fn madvise(addr: *mut c_void, len: usize, advice: i32) -> i32;
    fn mlock(addr: *const c_void, len: usize) -> i32;
    fn munmap(addr: *mut c_void, len: usize) -> i32;
}
