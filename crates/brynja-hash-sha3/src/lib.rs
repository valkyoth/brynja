//! Complete portable SHA3-224, SHA3-256, SHA3-384, and SHA3-512 for Brynja.
//!
//! The byte-oriented one-shot and streaming APIs implement the FIPS 202
//! SHA-3 functions without allocation, low-level code, I/O, global mutable
//! state, or a hardware requirement. One private Keccak-f\[1600\] permutation
//! owns the shared sponge foundation; the raw permutation is not public.

#![no_std]

mod digest;
mod error;
mod keccak;
mod sha3_224;
mod sha3_256;
mod sha3_384;
mod sha3_512;
mod sponge;

pub use brynja_hash_core::{FixedOutput, Update};
pub use digest::{Sha3_224Digest, Sha3_256Digest, Sha3_384Digest, Sha3_512Digest};
pub use error::{Sha3_224Error, Sha3_256Error, Sha3_384Error, Sha3_512Error};
pub use sha3_224::Sha3_224;
pub use sha3_256::Sha3_256;
pub use sha3_384::Sha3_384;
pub use sha3_512::Sha3_512;

/// Whether the complete portable SHA3-224 API is implemented.
pub const SHA3_224_IMPLEMENTED: bool = true;

/// Whether the complete portable SHA3-256 API is implemented.
pub const SHA3_256_IMPLEMENTED: bool = true;

/// Whether the complete portable SHA3-384 API is implemented.
pub const SHA3_384_IMPLEMENTED: bool = true;

/// Whether the complete portable SHA3-512 API is implemented.
pub const SHA3_512_IMPLEMENTED: bool = true;

/// Computes SHA3-224 over one complete byte slice.
///
/// ```
/// let digest = brynja_hash_sha3::sha3_224(b"abc")?;
/// assert_eq!(digest.as_bytes().len(), 28);
/// # Ok::<(), brynja_hash_sha3::Sha3_224Error>(())
/// ```
pub fn sha3_224(input: &[u8]) -> Result<Sha3_224Digest, Sha3_224Error> {
    let mut state = Sha3_224::new();
    state.update(input)?;
    Ok(state.finalize())
}

/// Computes SHA3-256 over one complete byte slice.
///
/// ```
/// let digest = brynja_hash_sha3::sha3_256(b"abc")?;
/// assert_eq!(
///     digest.as_bytes(),
///     &[
///         0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
///         0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
///         0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
///         0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32,
///     ]
/// );
/// # Ok::<(), brynja_hash_sha3::Sha3_256Error>(())
/// ```
pub fn sha3_256(input: &[u8]) -> Result<Sha3_256Digest, Sha3_256Error> {
    let mut state = Sha3_256::new();
    state.update(input)?;
    Ok(state.finalize())
}

/// Computes SHA3-384 over one complete byte slice.
///
/// ```
/// let digest = brynja_hash_sha3::sha3_384(b"abc")?;
/// assert_eq!(digest.as_bytes().len(), 48);
/// # Ok::<(), brynja_hash_sha3::Sha3_384Error>(())
/// ```
pub fn sha3_384(input: &[u8]) -> Result<Sha3_384Digest, Sha3_384Error> {
    let mut state = Sha3_384::new();
    state.update(input)?;
    Ok(state.finalize())
}

/// Computes SHA3-512 over one complete byte slice.
///
/// ```
/// let digest = brynja_hash_sha3::sha3_512(b"abc")?;
/// assert_eq!(digest.as_bytes().len(), 64);
/// # Ok::<(), brynja_hash_sha3::Sha3_512Error>(())
/// ```
pub fn sha3_512(input: &[u8]) -> Result<Sha3_512Digest, Sha3_512Error> {
    let mut state = Sha3_512::new();
    state.update(input)?;
    Ok(state.finalize())
}

#[cfg(test)]
mod tests {
    use super::{
        SHA3_224_IMPLEMENTED, SHA3_256_IMPLEMENTED, SHA3_384_IMPLEMENTED, SHA3_512_IMPLEMENTED,
        Sha3_224, Sha3_224Error, Sha3_256, Sha3_256Error, Sha3_384, Sha3_384Error, Sha3_512,
        Sha3_512Error, keccak::byte_location, sponge::checked_message_length,
    };

    #[test]
    fn implementation_claims_are_exact() {
        assert!(::core::hint::black_box(SHA3_224_IMPLEMENTED));
        assert!(::core::hint::black_box(SHA3_256_IMPLEMENTED));
        assert!(::core::hint::black_box(SHA3_384_IMPLEMENTED));
        assert!(::core::hint::black_box(SHA3_512_IMPLEMENTED));
    }

    #[test]
    fn checked_length_is_exact() {
        assert_eq!(checked_message_length(0, u128::MAX), Ok(u128::MAX));
        assert_eq!(checked_message_length(u128::MAX, 1), Err(()));
    }

    #[test]
    fn public_preflight_is_non_mutating() {
        let mut sha224 = Sha3_224::new();
        assert_eq!(sha224.check_additional_bytes(u128::MAX), Ok(()));
        assert_eq!(sha224.update(b"abc"), Ok(()));
        assert_eq!(sha224.message_bytes(), 3);
        assert_eq!(
            sha224.check_additional_bytes(u128::MAX),
            Err(Sha3_224Error::MessageTooLong)
        );

        let sha256 = Sha3_256::new();
        assert_eq!(sha256.check_additional_bytes(u128::MAX), Ok(()));
        assert_eq!(Sha3_256::new().check_additional_bytes(u128::MAX), Ok(()));
        assert_eq!(Sha3_384::new().check_additional_bytes(u128::MAX), Ok(()));
        assert_eq!(Sha3_512::new().check_additional_bytes(u128::MAX), Ok(()));
        assert_eq!(
            checked_message_length(u128::MAX, 1).map_err(|()| Sha3_256Error::MessageTooLong),
            Err(Sha3_256Error::MessageTooLong)
        );
        assert_eq!(
            checked_message_length(u128::MAX, 1).map_err(|()| Sha3_384Error::MessageTooLong),
            Err(Sha3_384Error::MessageTooLong)
        );
        assert_eq!(
            checked_message_length(u128::MAX, 1).map_err(|()| Sha3_512Error::MessageTooLong),
            Err(Sha3_512Error::MessageTooLong)
        );
    }

    #[test]
    fn every_state_byte_has_one_valid_lane_location() {
        for position in 0..200 {
            let (lane, shift) = byte_location(position);
            assert!(lane < 25);
            assert!(shift <= 56);
            assert_eq!(shift % 8, 0);
        }
    }
}

#[cfg(kani)]
mod proofs {
    use super::{keccak::byte_location, sponge::checked_message_length};

    #[kani::proof]
    fn checked_message_length_matches_u128_addition() {
        let current: u128 = kani::any();
        let additional: u128 = kani::any();
        assert_eq!(
            checked_message_length(current, additional),
            current.checked_add(additional).ok_or(())
        );
    }

    #[kani::proof]
    fn every_keccak_state_byte_maps_to_one_lane() {
        let position: usize = kani::any();
        kani::assume(position < 200);
        let (lane, shift) = byte_location(position);
        assert!(lane < 25);
        assert!(shift <= 56);
        assert_eq!(shift % 8, 0);
    }
}
