#![no_std]
#[allow(dead_code)] // Offline preparation is deliberately not an exported C capability.
mod image_admission;
include!("trusted_policy.rs");

/// # Safety
/// The private file guard provides `length` immutable readable bytes for this call.
/// No candidate-supplied policy or pointer is retained.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ProbeImageCheck(pointer: *const u8, length: usize) -> i32 {
    if pointer.is_null() || !(512..=16 * 1024 * 1024).contains(&length) {
        return 0;
    }
    // SAFETY: same bounded public-file allocation as the reviewed pin guard.
    let bytes = unsafe { core::slice::from_raw_parts(pointer, length) };
    i32::from(image_admission::admit(bytes, &TRUSTED_POLICY).is_ok())
}
unsafe extern "C" {
    fn ProbeImageAbort() -> !;
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: private native abort boundary; abort is not cleanup proof.
    unsafe { ProbeImageAbort() }
}
