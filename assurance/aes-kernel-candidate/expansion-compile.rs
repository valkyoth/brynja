//! no_std shape controls for internal expansion candidates; never executed.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "x86_64")]
#[path = "../../crates/brynja-crypto-cpu/src/aes/x86_expand.rs"]
mod candidate;
#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
#[path = "../../crates/brynja-crypto-cpu/src/aes/aarch64_expand.rs"]
mod candidate;

macro_rules! probe {
    ($name:ident, $k:literal, $s:literal) => {
        /// # Safety
        /// Caller supplies the exact CPU bundle and buffer lifetime/clearing.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(key: &[u8; $k], schedule: &mut [u8; $s]) {
            // SAFETY: Delegated ISA obligation; object-only compile control.
            unsafe { candidate::expand(key, schedule) }
        }
    };
}
probe!(aes_expansion_128, 16, 176);
probe!(aes_expansion_192, 24, 208);
probe!(aes_expansion_256, 32, 240);
#[cfg(invalid_zero_key)]
probe!(aes_expansion_invalid, 0, 176);
#[cfg(invalid_short_schedule)]
probe!(aes_expansion_invalid, 16, 160);
#[cfg(invalid_mismatched_schedule)]
probe!(aes_expansion_invalid, 16, 208);
#[cfg(invalid_wide_key)]
probe!(aes_expansion_invalid, 24, 176);
#[cfg(invalid_long_schedule)]
probe!(aes_expansion_invalid, 32, 256);
