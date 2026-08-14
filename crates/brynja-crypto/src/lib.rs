//! First-party cryptographic composition for Brynja.
//!
//! The complete portable SHA-256 implementation is exposed from its small
//! family crate. Provider effects, AEADs, KDFs, public-key algorithms, and the
//! complete planned composition layer remain unimplemented.

#![no_std]

/// Whether this package provides its planned implementation.
///
/// The foundation release intentionally reports `false`.
pub const IMPLEMENTED: bool = false;

/// Whether portable SHA-256 is implemented and available through this layer.
pub const SHA256_IMPLEMENTED: bool = true;

pub use brynja_hash_sha2::{FixedOutput, Sha256, Sha256Digest, Sha256Error, Update, sha256};

#[cfg(test)]
mod tests {
    #[test]
    fn foundation_does_not_claim_implementation() {
        assert!(!::core::hint::black_box(super::IMPLEMENTED));
        assert!(::core::hint::black_box(super::SHA256_IMPLEMENTED));
    }
}
