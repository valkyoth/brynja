//! no_std monomorphization controls, never linked into a production API.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "x86_64")]
#[path = "../../crates/brynja-crypto-cpu/src/aes/x86.rs"]
mod kernel;
#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
#[path = "../../crates/brynja-crypto-cpu/src/aes/aarch64.rs"]
mod kernel;

macro_rules! probe {
    ($name:ident, $n:literal) => {
        /// Compile-only unsafe probe; caller must supply the kernel's ISA bundle.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(
            state: &mut [u8; 16],
            schedule: &[[u8; 16]; $n],
            inverse: bool,
        ) {
            // SAFETY: ISA availability is delegated to this unsafe probe's
            // caller. These object files are compiled, not executed.
            unsafe { kernel::transform(state, schedule, inverse) }
        }
    };
}

probe!(aes_candidate_128, 11);
probe!(aes_candidate_192, 13);
probe!(aes_candidate_256, 15);
#[cfg(invalid_aes_schedule)]
probe!(aes_candidate_invalid, 10);
