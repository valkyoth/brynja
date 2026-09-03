//! Complete portable FIPS 202 SHA-3 and SHAKE functions for Brynja.
//!
//! Byte and canonical FIPS 202 arbitrary-bit one-shot, streaming, and SHAKE
//! output APIs implement the six standardized functions without allocation,
//! low-level code, I/O, global mutable state, or a hardware requirement. One
//! private Keccak-f\[1600\] permutation owns the shared sponge foundation.

#![no_std]

mod bit_api;
mod bit_string;
mod cshake;
mod digest;
mod error;
mod hardened;
mod keccak;
mod sha3_224;
mod sha3_256;
mod sha3_384;
mod sha3_512;
mod shake128;
mod shake256;
mod sp800185;
mod sponge;

pub use bit_api::{
    sha3_224_bits, sha3_256_bits, sha3_384_bits, sha3_512_bits, shake128_bits, shake256_bits,
};
pub use bit_string::{Fips202BitString, Fips202BitsError, Fips202Output};
pub use brynja_hash_core::{ExtendableOutput, FixedOutput, Update, XofReader};
pub use cshake::{
    Cshake128, Cshake128Reader, Cshake256, Cshake256Reader, cshake128, cshake128_bits, cshake256,
    cshake256_bits,
};
pub use digest::{Sha3_224Digest, Sha3_256Digest, Sha3_384Digest, Sha3_512Digest};
pub use error::{
    Cshake128Error, Cshake256Error, Sha3_224Error, Sha3_256Error, Sha3_384Error, Sha3_512Error,
    Shake128Error, Shake256Error,
};
pub use hardened::{
    HardenedCshake128, HardenedCshake128Reader, HardenedCshake256, HardenedCshake256Reader,
    HardenedFips202Construction, HardenedFips202State, HardenedSha3_224, HardenedSha3_256,
    HardenedSha3_384, HardenedSha3_512, HardenedSha3Error, HardenedSha3SecretOutput,
    HardenedShake128, HardenedShake128Reader, HardenedShake256, HardenedShake256Reader,
    Sha3PublicDeclassification,
};
pub use sha3_224::Sha3_224;
pub use sha3_256::Sha3_256;
pub use sha3_384::Sha3_384;
pub use sha3_512::Sha3_512;
pub use shake128::{Shake128, Shake128Reader};
pub use shake256::{Shake256, Shake256Reader};
pub use sp800185::{
    EncodedBitLength, EncodedInteger, Sp800185EncodingError, Sp800185Integer, bytepad,
    encode_string, left_encode, left_encode_u128, right_encode, right_encode_u128,
};

/// Whether the complete portable SHA3-224 API is implemented.
pub const SHA3_224_IMPLEMENTED: bool = true;

/// Whether the complete portable SHA3-256 API is implemented.
pub const SHA3_256_IMPLEMENTED: bool = true;

/// Whether the complete portable SHA3-384 API is implemented.
pub const SHA3_384_IMPLEMENTED: bool = true;

/// Whether the complete portable SHA3-512 API is implemented.
pub const SHA3_512_IMPLEMENTED: bool = true;

/// Whether the complete portable SHAKE128 API is implemented.
pub const SHAKE128_IMPLEMENTED: bool = true;

/// Whether the complete portable SHAKE256 API is implemented.
pub const SHAKE256_IMPLEMENTED: bool = true;

/// Whether all six identities accept canonical arbitrary-bit messages.
pub const FIPS202_BIT_INPUT_IMPLEMENTED: bool = true;

/// Whether both SHAKE identities emit canonical arbitrary-bit output.
pub const FIPS202_BIT_OUTPUT_IMPLEMENTED: bool = true;

/// Whether all six FIPS 202 identities expose hardened secret-bearing state.
pub const FIPS202_HARDENED_STATE_IMPLEMENTED: bool = true;

/// Whether all SP 800-185 encoding functions and both cSHAKE strengths are implemented.
pub const CSHAKE_IMPLEMENTED: bool = true;

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

/// Computes exactly `output.len()` bytes of SHAKE128 output.
///
/// The empty output slice is valid. Use [`Shake128`] for streamed input or
/// [`Shake128Reader`] for incremental output.
///
/// ```
/// let mut output = [0_u8; 32];
/// brynja_hash_sha3::shake128(b"", &mut output)?;
/// assert_eq!(&output[..4], &[0x7f, 0x9c, 0x2b, 0xa4]);
/// # Ok::<(), brynja_hash_sha3::Shake128Error>(())
/// ```
pub fn shake128(input: &[u8], output: &mut [u8]) -> Result<(), Shake128Error> {
    let mut state = Shake128::new();
    state.update(input)?;
    state.finalize_xof().squeeze(output)
}

/// Computes exactly `output.len()` bytes of SHAKE256 output.
///
/// The empty output slice is valid. Use [`Shake256`] for streamed input or
/// [`Shake256Reader`] for incremental output.
///
/// ```
/// let mut output = [0_u8; 64];
/// brynja_hash_sha3::shake256(b"", &mut output)?;
/// assert_eq!(&output[..4], &[0x46, 0xb9, 0xdd, 0x2b]);
/// # Ok::<(), brynja_hash_sha3::Shake256Error>(())
/// ```
pub fn shake256(input: &[u8], output: &mut [u8]) -> Result<(), Shake256Error> {
    let mut state = Shake256::new();
    state.update(input)?;
    state.finalize_xof().squeeze(output)
}

#[cfg(test)]
mod tests {
    use super::{
        CSHAKE_IMPLEMENTED, FIPS202_BIT_INPUT_IMPLEMENTED, FIPS202_BIT_OUTPUT_IMPLEMENTED,
        FIPS202_HARDENED_STATE_IMPLEMENTED, SHA3_224_IMPLEMENTED, SHA3_256_IMPLEMENTED,
        SHA3_384_IMPLEMENTED, SHA3_512_IMPLEMENTED, SHAKE128_IMPLEMENTED, SHAKE256_IMPLEMENTED,
        Sha3_224, Sha3_224Error, Sha3_256, Sha3_256Error, Sha3_384, Sha3_384Error, Sha3_512,
        Sha3_512Error, Shake128, Shake128Error, Shake256, Shake256Error,
        keccak::byte_location,
        sponge::{checked_message_length, checked_output_length},
    };

    #[test]
    fn implementation_claims_are_exact() {
        assert!(::core::hint::black_box(SHA3_224_IMPLEMENTED));
        assert!(::core::hint::black_box(SHA3_256_IMPLEMENTED));
        assert!(::core::hint::black_box(SHA3_384_IMPLEMENTED));
        assert!(::core::hint::black_box(SHA3_512_IMPLEMENTED));
        assert!(::core::hint::black_box(SHAKE128_IMPLEMENTED));
        assert!(::core::hint::black_box(SHAKE256_IMPLEMENTED));
        assert!(::core::hint::black_box(FIPS202_BIT_INPUT_IMPLEMENTED));
        assert!(::core::hint::black_box(FIPS202_BIT_OUTPUT_IMPLEMENTED));
        assert!(::core::hint::black_box(FIPS202_HARDENED_STATE_IMPLEMENTED));
        assert!(::core::hint::black_box(CSHAKE_IMPLEMENTED));
    }

    #[test]
    fn checked_length_is_exact() {
        assert_eq!(checked_message_length(0, u128::MAX), Ok(u128::MAX));
        assert_eq!(checked_message_length(u128::MAX, 1), Err(()));
        assert_eq!(checked_output_length(0, u128::MAX), Ok(u128::MAX));
        assert_eq!(checked_output_length(u128::MAX, 1), Err(()));
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
        let shake128 = Shake128::new();
        let shake256 = Shake256::new();
        assert_eq!(shake128.check_additional_bytes(u128::MAX), Ok(()));
        assert_eq!(shake256.check_additional_bytes(u128::MAX), Ok(()));
        assert_eq!(shake128.message_bytes(), 0);
        assert_eq!(shake256.message_bytes(), 0);
        assert_eq!(
            checked_message_length(u128::MAX, 1).map_err(|()| Shake128Error::MessageTooLong),
            Err(Shake128Error::MessageTooLong)
        );
        assert_eq!(
            checked_output_length(u128::MAX, 1).map_err(|()| Shake256Error::OutputTooLong),
            Err(Shake256Error::OutputTooLong)
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
    use super::{
        keccak::byte_location,
        sponge::{checked_message_length, checked_output_length},
    };

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

    #[kani::proof]
    fn checked_output_length_matches_u128_addition() {
        let current: u128 = kani::any();
        let additional: u128 = kani::any();
        assert_eq!(
            checked_output_length(current, additional),
            current.checked_add(additional).ok_or(())
        );
    }
}
