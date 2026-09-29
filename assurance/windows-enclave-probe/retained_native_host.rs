//! Private native adapter for fixed PUBLIC vectors. Not a shipped backend.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
use core::{ffi::c_void, num::NonZeroU64, ptr::NonNull};
mod retained_model;
use retained_model::transport::{Driver, Outcome, Receipt};
use retained_model::{Error, PublicVector, Session, State};

unsafe extern "C" {
    fn HostOpen(image: *const u16) -> *mut c_void;
    fn HostClose(instance: *mut c_void) -> i32;
    fn HostCounter(which: u64) -> u64;
    #[cfg(not(test))]
    fn HostAbort() -> !;
    fn RetainedRun(
        instance: *mut c_void,
        operation: u64,
        output: *mut u8,
        report: *mut [u64; 4],
    ) -> i32;
}

struct Resource {
    pointer: Option<NonNull<c_void>>,
    identity: NonZeroU64,
    generation: u64,
    live: bool,
    fault: u8,
}
impl Resource {
    fn call(&mut self, operation: u64, output: *mut u8, expected: [u64; 4]) -> Result<(), ()> {
        let pointer = self.pointer.ok_or(())?;
        let mut report = [0; 4];
        // SAFETY: uniquely owned, thread-bound instance. Calls are synchronous;
        // output is null or an exclusive live 32-byte PUBLIC staging buffer.
        let result = unsafe { RetainedRun(pointer.as_ptr(), operation, output, &mut report) };
        if result != 1 || report != expected {
            return Err(());
        }
        Ok(())
    }
    fn clear(&mut self) -> Result<(), ()> {
        if self.live {
            // Only destruction reports full-page zero readback + unlock/free.
            self.call(3, core::ptr::null_mut(), [4, 0, 4096, 1])?;
            self.live = false;
        }
        Ok(())
    }
    fn receipt(&self, generation: u64, outcome: Outcome) -> Receipt {
        Receipt {
            identity: self.identity.get(),
            generation,
            outcome,
            worker_clear: true,
            result_clear: outcome != Outcome::Ready,
            deleted: outcome == Outcome::Released,
        }
    }
    fn close(&mut self) -> Result<(), ()> {
        self.clear()?;
        if let Some(pointer) = self.pointer {
            // SAFETY: no active call/borrow; C frees only after confirmed deletion.
            if unsafe { HostClose(pointer.as_ptr()) } != 1 {
                return Err(());
            }
            self.pointer = None;
        }
        Ok(())
    }
}
impl Driver for Resource {
    fn begin(&mut self, vector: u8, generation: u64) -> Result<Receipt, ()> {
        if self.live || vector >= 20 || self.generation.checked_add(1) != Some(generation) {
            return Err(());
        }
        // Assume responsibility BEFORE entry, including a lost creation reply.
        self.live = true;
        self.generation = generation;
        self.call(0, core::ptr::null_mut(), [1, 0, 0, 0])?;
        self.call(
            1 | (u64::from(vector) << 8),
            core::ptr::null_mut(),
            [2, 1, 0, 0],
        )?;
        Ok(self.receipt(generation, Outcome::Ready))
    }
    fn export(&mut self, generation: u64, staging: &mut [u8; 32]) -> Result<Receipt, ()> {
        if !self.live || generation != self.generation {
            return Err(());
        }
        if self.fault == 1 {
            self.call(6, staging.as_mut_ptr(), [105, 0, 0, 0])?;
            return Err(()); // actual null-destination OS copy rejection
        }
        self.call(2, staging.as_mut_ptr(), [3, 0, 0, 0])?;
        if self.fault == 2 {
            return Err(());
        } // simulated lost completion AFTER real export
        self.clear()?;
        let mut receipt = self.receipt(generation, Outcome::Exported);
        if self.fault == 3 {
            receipt.identity ^= 1;
        } // wrong-resource receipt control
        Ok(receipt)
    }
    fn cancel(&mut self, generation: u64) -> Result<Receipt, ()> {
        if !self.live || generation != self.generation {
            return Err(());
        }
        self.call(4, core::ptr::null_mut(), [5, 0, 0, 0])?;
        self.clear()?;
        Ok(self.receipt(generation, Outcome::Cancelled))
    }
    fn release(&mut self, generation: u64) -> Result<Receipt, ()> {
        if generation != self.generation {
            return Err(());
        }
        self.close()?;
        Ok(self.receipt(generation, Outcome::Released))
    }
}
impl Drop for Resource {
    fn drop(&mut self) {
        // If clearing/deletion is unconfirmed, C allocation remains retained.
        // No free/unlock fallback, and no destructor receipt is fabricated.
        let _ = self.close();
    }
}
fn open(image: &[u16], fault: u8) -> Option<Session<Resource>> {
    if image.is_empty() || image.last() != Some(&0) || image[..image.len() - 1].contains(&0) {
        return None;
    }
    // SAFETY: bounded live NUL-terminated path, native constructor is synchronous.
    let pointer = NonNull::new(unsafe { HostOpen(image.as_ptr()) })?;
    // Private routing identity; never supplied as authority by a public caller.
    let identity = NonZeroU64::new(pointer.as_ptr().addr() as u64)?;
    Some(Session::from_driver(
        Resource {
            pointer: Some(pointer),
            identity,
            generation: 0,
            live: false,
            fault,
        },
        identity,
    ))
}

mod retained_native_campaign;

/// # Safety
/// C supplies a live argv path of exactly length UTF-16 units including NUL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn HostCampaign(image: *const u16, length: usize) -> u32 {
    if image.is_null() || length == 0 || length > 32768 {
        return 1;
    }
    let image = unsafe { core::slice::from_raw_parts(image, length) };
    retained_native_campaign::run(image)
}
#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    // No unwind crosses C; abort is not cleanup evidence.
    unsafe { HostAbort() }
}

#[cfg(test)]
#[path = "retained_native_adapter_tests.rs"]
mod tests;
