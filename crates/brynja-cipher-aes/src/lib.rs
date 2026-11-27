//! Raw AES-128/192/256 blocks; not message encryption or authentication.
//! No default features. Portable owners never select hardware implicitly.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "hazmat-aes-block")]
pub mod aes;
#[cfg(all(feature = "__mode", not(feature = "hazmat-aes-block")))]
#[allow(dead_code, unused_imports)]
mod aes;

#[cfg(feature = "__mode")]
#[doc(hidden)]
pub mod __mode;

#[cfg(feature = "external-key-provider")]
pub mod provider;
