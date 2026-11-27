//! Compatibility view of the [standalone GMAC owners](brynja_aead_gcm::gmac).
//! See that module for nonce reservation and verification-only use.
//! The execution namespace follows this crate's own opt-in, not unified leaf features.
#[cfg(feature = "gmac-execution")]
pub use brynja_aead_gcm::gmac::execution;
pub use brynja_aead_gcm::gmac::{Aes128Gmac, Aes192Gmac, Aes256Gmac, GmacError, GmacTag};
