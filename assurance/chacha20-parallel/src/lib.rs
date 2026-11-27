//! Benchmark adapter for the actual, explicitly selected streaming owner.
#![no_std]
#![deny(unsafe_code)]

#[cfg(all(target_arch = "riscv64", target_os = "linux"))]
mod rvv;
#[cfg(all(target_arch = "riscv64", target_os = "linux"))]
pub use rvv::{available, record, try_record};

#[cfg(target_arch = "aarch64")]
pub use brynja_cipher_chacha::ChaCha20Neon as Selected;
#[cfg(target_arch = "x86_64")]
pub use brynja_cipher_chacha::ChaCha20Sse2 as Selected;
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
use brynja_cipher_chacha::Error;

/// Process one aligned-start request through the target's explicit SIMD owner.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
pub fn record(key: &[u8; 32], nonce: [u8; 12], first: u32, data: &mut [u8]) -> Result<(), Error> {
    Selected::new(key, nonce, first).apply_keystream_in_place(data)
}
