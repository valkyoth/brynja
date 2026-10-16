//! Apple Silicon Darwin mapping ABI only; no foreign cryptography.
#![allow(unsafe_code)]
use super::{Error, Layout};
use core::{ffi::c_void, ptr::NonNull};
#[cfg(test)]
mod observe;
#[cfg(test)]
mod tests;
mod thread;

pub(in super::super) struct Mapping {
    base: Option<NonNull<u8>>,
    data: NonNull<u8>,
    layout: Layout,
    used: usize,
    admitted: bool,
}
impl Mapping {
    pub(in super::super) fn new(bytes: usize, max: usize) -> Result<Self, Error> {
        let page = usize::try_from(getpagesize()).map_err(|_| Error::InvalidSize)?;
        let layout = Layout::new(bytes, max, page)?;
        fault(Step::Map, Error::Mapping)?;
        // SAFETY: dedicated anonymous non-executable PROT_NONE reservation;
        // no MAP_FIXED or caller mapping, checked positive size, Darwin flags.
        let raw = unsafe { mmap(core::ptr::null_mut(), layout.total, 0, 0x1002, -1, 0) };
        if raw as usize == usize::MAX {
            return Err(Error::Mapping);
        }
        let Some(base) = NonNull::new(raw.cast::<u8>()) else {
            // SAFETY: successful address-zero reservation cannot back references.
            let _ = unsafe { munmap(raw, layout.total) };
            return Err(Error::Mapping);
        };
        // SAFETY: first payload byte lies inside the fresh mapping after its guard.
        let data = unsafe { NonNull::new_unchecked(base.as_ptr().add(layout.page)) };
        let mut owner = Self {
            base: Some(base),
            data,
            layout,
            used: bytes,
            admitted: false,
        };
        fault(Step::Fork, Error::ForkExclusion)?;
        // SAFETY: current task port and entire live reservation, VM_INHERIT_NONE=2.
        // Deployment forbids fork racing construction or while resources are live.
        let code = unsafe {
            mach_vm_inherit(
                mach_task_self_,
                base.as_ptr() as u64,
                layout.total as u64,
                2,
            )
        };
        check(code, Error::ForkExclusion)?;
        fault(Step::Access, Error::Access)?;
        check(
            // SAFETY: RW applies to page-aligned payload only, preserving both guards.
            unsafe { mprotect(data.as_ptr().cast(), layout.payload, 3) },
            Error::Access,
        )?;
        fault(Step::Lock, Error::Lock)?;
        check(
            // SAFETY: exact live RW payload. mlock acquires residency, NOT dump exclusion.
            unsafe { mlock(data.as_ptr().cast(), layout.payload) },
            Error::Lock,
        )?;
        owner.admitted = true;
        Ok(owner)
    }
    pub(in super::super) fn bytes(&self) -> &[u8] {
        // SAFETY: only admitted live owners escape construction; zero-initialized
        // anonymous bytes, used <= payload <= isize::MAX, loan excludes release.
        unsafe { core::slice::from_raw_parts(self.data.as_ptr(), self.used) }
    }
    pub(in super::super) fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: exclusive owner loan of the live initialized used region.
        unsafe { core::slice::from_raw_parts_mut(self.data.as_ptr(), self.used) }
    }
    pub(in super::super) fn clear(&mut self) {
        if self.base.is_none() || !self.admitted {
            return;
        }
        // SAFETY: whole owned payload is RW and excludes both guards. No worker
        // or loan may still be active; stack clearing occurs only after join.
        let bytes =
            unsafe { core::slice::from_raw_parts_mut(self.data.as_ptr(), self.layout.payload) };
        let _ = brynja_core::clear_owned_region(bytes);
        #[cfg(test)]
        tests::cleared(bytes.iter().all(|byte| *byte == 0));
    }
    fn close(&mut self) -> Result<(), Error> {
        let Some(base) = self.base else {
            return Ok(());
        };
        self.clear();
        fault(Step::Unmap, Error::Release)?;
        check(
            // SAFETY: full dedicated reservation, no live worker/loan. Unmapping
            // releases locks without an unlocked interval before clearing.
            unsafe { munmap(base.as_ptr().cast(), self.layout.total) },
            Error::Release,
        )?;
        self.base = None;
        self.admitted = false;
        self.used = 0;
        Ok(())
    }
    pub(in super::super) fn run<F: FnOnce() + Send>(&mut self, work: F) -> Result<(), Error> {
        thread::run(self, work)
    }
    #[cfg(test)]
    pub(in super::super) fn verify_native(&self) -> Result<(), Error> {
        observe::verify(self)
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        // If the OS refuses release, leak cleared storage instead of reusing it.
        let _ = self.close();
    }
}
fn check(code: i32, error: Error) -> Result<(), Error> {
    if code == 0 { Ok(()) } else { Err(error) }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Step {
    Map,
    Fork,
    Access,
    Lock,
    Unmap,
    Init,
    Stack,
    Create,
    #[cfg(test)]
    Join,
    Destroy,
}
fn fault(step: Step, error: Error) -> Result<(), Error> {
    #[cfg(test)]
    if tests::hit(step) {
        return Err(error);
    }
    let _ = (step, error);
    Ok(())
}

unsafe extern "C" {
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
}
