//! First-party cryptographic composition for Brynja.
//!
//! Complete portable SHA-224, SHA-256, SHA-384, and SHA-512 implementations are
//! exposed from their small family crate. Provider effects, AEADs, KDFs, public-key
//! algorithms, and the complete planned composition layer remain unimplemented.

#![no_std]

/// Whether this package provides its planned implementation.
///
/// The foundation release intentionally reports `false`.
pub const IMPLEMENTED: bool = false;

/// Whether portable SHA-256 is implemented and available through this layer.
pub const SHA256_IMPLEMENTED: bool = true;

/// Whether portable SHA-224 is implemented and available through this layer.
pub const SHA224_IMPLEMENTED: bool = true;

/// Whether portable SHA-384 is implemented and available through this layer.
pub const SHA384_IMPLEMENTED: bool = true;

/// Whether portable SHA-512 is implemented and available through this layer.
pub const SHA512_IMPLEMENTED: bool = true;

pub use brynja_hash_sha2::{
    FixedOutput, Sha224, Sha224Digest, Sha224Error, Sha256, Sha256Digest, Sha256Error, Sha384,
    Sha384Digest, Sha384Error, Sha512, Sha512Digest, Sha512Error, Update, sha224, sha256, sha384,
    sha512,
};

#[cfg(test)]
mod tests {
    #[test]
    fn foundation_does_not_claim_implementation() {
        assert!(!::core::hint::black_box(super::IMPLEMENTED));
        assert!(::core::hint::black_box(super::SHA224_IMPLEMENTED));
        assert!(::core::hint::black_box(super::SHA256_IMPLEMENTED));
        assert!(::core::hint::black_box(super::SHA384_IMPLEMENTED));
        assert!(::core::hint::black_box(super::SHA512_IMPLEMENTED));
        assert_eq!(
            super::sha224(b"abc"),
            Ok(super::Sha224Digest::from_bytes([
                0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22, 0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2,
                0x55, 0xb3, 0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7, 0xe3, 0x6c, 0x9d, 0xa7,
            ]))
        );
    }
}
