//! Isolated public-vector host experiment. No shipped API or confidential inputs.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

use core::{ffi::c_void, ptr::NonNull};
mod native_model;
use native_model::{
    Disposition, Error, NativeDriver, Outcome, Pending, PublicInput, Session, State,
};

unsafe extern "C" {
    fn HostOpen(image: *const u16) -> *mut c_void;
    fn HostClose(instance: *mut c_void) -> i32;
    fn HostCounter(which: u64) -> u64;
    fn HostAbort() -> !;
    fn HostRun(
        instance: *mut c_void,
        user: *mut c_void,
        callback: Protocol,
        request: *const u8,
        command: *mut u8,
        output: *mut u8,
        fault: u64,
        report: *mut [u64; 4],
    ) -> i32;
}
type Protocol = unsafe extern "C" fn(*mut c_void, u64, *mut u8, *const u8) -> i32;

struct Resource(Option<NonNull<c_void>>);
impl Resource {
    fn close(&mut self) -> bool {
        let Some(pointer) = self.0 else { return true };
        // The resource is private, uniquely owned, and every HostRun is synchronous.
        if unsafe { HostClose(pointer.as_ptr()) } != 1 {
            return false;
        }
        self.0 = None;
        true
    }
}
impl Drop for Resource {
    fn drop(&mut self) {
        // A failed OS delete remains recorded as retained; Drop is not a success proof.
        let _ = self.close();
    }
}
struct Host {
    resource: Resource,
    session: Session,
}
impl Host {
    fn open(image: &[u16]) -> Option<Self> {
        if image.is_empty() || image.last() != Some(&0) || image[..image.len() - 1].contains(&0) {
            return None;
        }
        // Bounded, live NUL-terminated path. C completes loading before returning.
        let pointer = NonNull::new(unsafe { HostOpen(image.as_ptr()) })?;
        Some(Self {
            resource: Resource(Some(pointer)),
            session: Session::new(),
        })
    }
    fn execute(
        &mut self,
        input: &[u8],
        disposition: Disposition<'_>,
        fault: u64,
    ) -> Result<Outcome, Error> {
        let Some(pointer) = self.resource.0 else {
            return Err(Error::Quarantined);
        };
        self.session.execute(
            PublicInput::acknowledge(input),
            disposition,
            &mut Driver { pointer, fault },
        )
    }
}
struct Driver {
    pointer: NonNull<c_void>,
    fault: u64,
}

unsafe extern "C" fn exchange(
    user: *mut c_void,
    step: u64,
    command: *mut u8,
    output: *const u8,
) -> i32 {
    if user.is_null() || command.is_null() || output.is_null() {
        return 0;
    }
    // Only HostRun's fixed synchronous TLS callback can reach this private function.
    // The driver retains Pending and both arrays until unregister + return. No Rust
    // references to either wire buffer are held across the foreign call.
    let pending = unsafe { &mut *user.cast::<Pending<'_, '_, '_>>() };
    let offer = unsafe { command.cast::<[u8; 64]>().read_unaligned() };
    let staging = unsafe { output.cast::<[u8; 32]>().read_unaligned() };
    match pending.native_exchange(step, &offer, &staging) {
        Ok(reply) => {
            unsafe { command.cast::<[u8; 64]>().write_unaligned(reply) };
            1
        }
        Err(_) => 0,
    }
}
impl NativeDriver for Driver {
    fn run(&mut self, pending: &mut Pending<'_, '_, '_>) -> Result<Outcome, Error> {
        let mut command = [0u8; 64];
        let mut output = [0u8; 32];
        let mut report = [0u64; 4];
        let request =
            pending.native_request(command.as_mut_ptr() as u64, output.as_mut_ptr() as u64)?;
        // Exclusive buffers and a unique pending borrow live across a bounded native
        // call. The callback cannot escape; unexpected callback threads fail closed.
        let ok = unsafe {
            HostRun(
                self.pointer.as_ptr(),
                (pending as *mut Pending<'_, '_, '_>).cast(),
                exchange,
                request.as_ptr(),
                command.as_mut_ptr(),
                output.as_mut_ptr(),
                self.fault,
                &mut report,
            )
        };
        pending.native_finish(ok == 1, report)
    }
}

mod campaign;

/// C wmain supplies a live NUL-terminated argv element of exactly length units.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn HostCampaign(image: *const u16, length: usize) -> u32 {
    if image.is_null() || length == 0 || length > 32768 {
        return 1;
    }
    let image = unsafe { core::slice::from_raw_parts(image, length) };
    campaign::run(image)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    // No unwind crosses C; a failed child is never accepted as cleanup evidence.
    unsafe { HostAbort() }
}
