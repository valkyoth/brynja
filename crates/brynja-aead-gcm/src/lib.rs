//! Detached AES-GCM and AAD-only GMAC over the standalone AES and GHASH crates.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(any(feature = "aes-gcm", feature = "gmac"))]
use brynja_cipher_aes::__mode as aes;
#[cfg(any(feature = "aes-gcm", feature = "gmac"))]
use brynja_universal_hash_ghash::__mode as ghash;

#[cfg(all(feature = "gmac", not(feature = "aes-gcm")))]
mod aes_gcm;
#[cfg(feature = "aes-gcm")]
pub mod aes_gcm;
#[cfg(feature = "gmac")]
pub use aes_gcm::portable::gmac;
