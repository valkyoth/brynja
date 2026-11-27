//! Compatibility view of the [standalone AES-GCM owners](brynja_aead_gcm::aes_gcm).
//! See that module for nonce reservation, scratch and authenticated opening contracts.
//! The execution namespace follows this crate's own opt-in, not unified leaf features.
#[cfg(feature = "aes-gcm-execution")]
pub use brynja_aead_gcm::aes_gcm::execution;
pub use brynja_aead_gcm::aes_gcm::{Aes128Gcm, Aes192Gcm, Aes256Gcm, GcmError};
