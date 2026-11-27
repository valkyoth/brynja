//! Portable RFC 8439 ChaCha20. Enable `hazmat-chacha20` to use the raw stream
//! cipher. It does not authenticate messages. Never reuse a key/nonce stream.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "hazmat-chacha20")]
mod chacha20;
#[cfg(feature = "hazmat-chacha20")]
pub use chacha20::{ChaCha20, Error};

#[cfg(all(
    feature = "chacha20-sse2",
    target_arch = "x86_64",
    target_feature = "sse2"
))]
pub use chacha20::execution::ParallelChaCha20 as ChaCha20Sse2;

#[cfg(all(
    feature = "chacha20-neon",
    target_arch = "aarch64",
    target_feature = "neon",
    target_endian = "little"
))]
pub use chacha20::execution::ParallelChaCha20 as ChaCha20Neon;
