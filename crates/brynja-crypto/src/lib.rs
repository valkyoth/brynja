//! First-party cryptographic composition for Brynja.
//!
//! All six complete portable FIPS 180-4 SHA-2 implementations and the complete
//! six complete portable FIPS 202 SHA-3 and SHAKE implementations are exposed from
//! their small family crates. Provider effects, AEADs, KDFs, public-key
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

/// Whether portable SHA-512/224 is implemented and available through this layer.
pub const SHA512_224_IMPLEMENTED: bool = true;

/// Whether portable SHA-512/256 is implemented and available through this layer.
pub const SHA512_256_IMPLEMENTED: bool = true;

/// Whether every SHA-2 identity accepts canonical arbitrary-bit messages.
pub const SHA2_BIT_INPUT_IMPLEMENTED: bool = true;

/// Whether all SHA-2 identities expose sealed secret-bearing state owners.
pub const SHA2_HARDENED_STATE_IMPLEMENTED: bool = true;

/// Whether portable SHA3-224 is implemented and available through this layer.
pub const SHA3_224_IMPLEMENTED: bool = true;

/// Whether portable SHA3-256 is implemented and available through this layer.
pub const SHA3_256_IMPLEMENTED: bool = true;

/// Whether portable SHA3-384 is implemented and available through this layer.
pub const SHA3_384_IMPLEMENTED: bool = true;

/// Whether portable SHA3-512 is implemented and available through this layer.
pub const SHA3_512_IMPLEMENTED: bool = true;

/// Whether portable SHAKE128 is implemented and available through this layer.
pub const SHAKE128_IMPLEMENTED: bool = true;

/// Whether portable SHAKE256 is implemented and available through this layer.
pub const SHAKE256_IMPLEMENTED: bool = true;

/// Whether canonical FIPS 202 arbitrary-bit input is exposed by this layer.
pub const FIPS202_BIT_INPUT_IMPLEMENTED: bool = true;

/// Whether canonical FIPS 202 arbitrary-bit SHAKE output is exposed here.
pub const FIPS202_BIT_OUTPUT_IMPLEMENTED: bool = true;

/// Whether all six FIPS 202 identities expose sealed hardened state owners.
pub const FIPS202_HARDENED_STATE_IMPLEMENTED: bool = true;

pub use brynja_hash_sha2::{
    BitString, BitStringError, FixedOutput, HardenedSha2Error, HardenedSha2State, HardenedSha224,
    HardenedSha256, HardenedSha384, HardenedSha512, HardenedSha512_224, HardenedSha512_256,
    PublicDeclassification, Sha224, Sha224Digest, Sha224Error, Sha256, Sha256Digest, Sha256Error,
    Sha384, Sha384Digest, Sha384Error, Sha512, Sha512_224, Sha512_224Digest, Sha512_224Error,
    Sha512_256, Sha512_256Digest, Sha512_256Error, Sha512Digest, Sha512Error, Update, sha224,
    sha224_bits, sha256, sha256_bits, sha384, sha384_bits, sha512, sha512_224, sha512_224_bits,
    sha512_256, sha512_256_bits, sha512_bits,
};
pub use brynja_hash_sha3::{
    ExtendableOutput, Fips202BitString, Fips202BitsError, Fips202Output,
    HardenedFips202Construction, HardenedFips202State, HardenedSha3_224, HardenedSha3_256,
    HardenedSha3_384, HardenedSha3_512, HardenedSha3Error, HardenedSha3SecretOutput,
    HardenedShake128, HardenedShake128Reader, HardenedShake256, HardenedShake256Reader, Sha3_224,
    Sha3_224Digest, Sha3_224Error, Sha3_256, Sha3_256Digest, Sha3_256Error, Sha3_384,
    Sha3_384Digest, Sha3_384Error, Sha3_512, Sha3_512Digest, Sha3_512Error,
    Sha3PublicDeclassification, Shake128, Shake128Error, Shake128Reader, Shake256, Shake256Error,
    Shake256Reader, XofReader, sha3_224, sha3_224_bits, sha3_256, sha3_256_bits, sha3_384,
    sha3_384_bits, sha3_512, sha3_512_bits, shake128, shake128_bits, shake256, shake256_bits,
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
        assert!(::core::hint::black_box(super::SHA512_224_IMPLEMENTED));
        assert!(::core::hint::black_box(super::SHA512_256_IMPLEMENTED));
        assert!(::core::hint::black_box(super::SHA2_BIT_INPUT_IMPLEMENTED));
        assert!(::core::hint::black_box(
            super::SHA2_HARDENED_STATE_IMPLEMENTED
        ));
        assert!(::core::hint::black_box(super::SHA3_224_IMPLEMENTED));
        assert!(::core::hint::black_box(super::SHA3_256_IMPLEMENTED));
        assert!(::core::hint::black_box(super::SHA3_384_IMPLEMENTED));
        assert!(::core::hint::black_box(super::SHA3_512_IMPLEMENTED));
        assert!(::core::hint::black_box(super::SHAKE128_IMPLEMENTED));
        assert!(::core::hint::black_box(super::SHAKE256_IMPLEMENTED));
        assert!(::core::hint::black_box(
            super::FIPS202_BIT_INPUT_IMPLEMENTED
        ));
        assert!(::core::hint::black_box(
            super::FIPS202_BIT_OUTPUT_IMPLEMENTED
        ));
        assert!(::core::hint::black_box(
            super::FIPS202_HARDENED_STATE_IMPLEMENTED
        ));
        assert_eq!(
            super::sha224(b"abc"),
            Ok(super::Sha224Digest::from_bytes([
                0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22, 0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2,
                0x55, 0xb3, 0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7, 0xe3, 0x6c, 0x9d, 0xa7,
            ]))
        );
        let bit_digest = super::BitString::new(&[0x60], 3)
            .ok()
            .and_then(|input| super::sha256_bits(input).ok());
        assert_eq!(
            bit_digest.as_ref().map(|digest| &digest.as_bytes()[..4]),
            Some(&[0x1f, 0x77, 0x94, 0xd4][..])
        );
        assert_eq!(
            super::sha3_256(b"abc"),
            Ok(super::Sha3_256Digest::from_bytes([
                0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3,
                0x90, 0xbd, 0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45,
                0x11, 0x43, 0x15, 0x32,
            ]))
        );
        assert_eq!(
            super::sha3_384(b"abc").map(|digest| digest.as_bytes().len()),
            Ok(48)
        );
        assert_eq!(
            super::sha3_512(b"abc").map(|digest| digest.as_bytes().len()),
            Ok(64)
        );
        let mut shake128 = [0_u8; 32];
        let mut shake256 = [0_u8; 64];
        assert_eq!(super::shake128(b"", &mut shake128), Ok(()));
        assert_eq!(super::shake256(b"", &mut shake256), Ok(()));
        assert_eq!(&shake128[..4], &[0x7f, 0x9c, 0x2b, 0xa4]);
        assert_eq!(&shake256[..4], &[0x46, 0xb9, 0xdd, 0x2b]);
    }
}
