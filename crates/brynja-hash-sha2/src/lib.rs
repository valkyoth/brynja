//! Complete portable SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and
//! SHA-512/256 for Brynja.
//!
//! The byte-oriented one-shot and streaming APIs implement FIPS 180-4
//! SHA-2 without allocation, low-level code, I/O, global mutable state, or a
//! hardware requirement. Each of the six FIPS 180-4 identities has a distinct
//! public type and exact initialization and output rules.

#![no_std]

mod compress;
mod compress64;
mod digest;
mod error;
mod sha224;
mod sha256;
mod sha384;
mod sha512;
mod sha512_224;
mod sha512_256;
mod sha512_state;
mod sha512_t;

pub use brynja_hash_core::{FixedOutput, Update};
pub use digest::{
    Sha224Digest, Sha256Digest, Sha384Digest, Sha512_224Digest, Sha512_256Digest, Sha512Digest,
};
pub use error::{
    Sha224Error, Sha256Error, Sha384Error, Sha512_224Error, Sha512_256Error, Sha512Error,
};
pub use sha224::Sha224;
pub use sha256::Sha256;
pub use sha384::Sha384;
pub use sha512::Sha512;
pub use sha512_224::Sha512_224;
pub use sha512_256::Sha512_256;

#[cfg(feature = "cpu")]
pub use brynja_crypto_cpu::{
    Sha256Backend, Sha256BackendError, Sha256BackendHealth, Sha256BackendReport,
    Sha256BackendSession, Sha512Backend, Sha512BackendError, Sha512BackendHealth,
    Sha512BackendReport, Sha512BackendSession,
};
#[cfg(feature = "cpu")]
pub use sha224::Sha224AcceleratedError;
#[cfg(feature = "cpu")]
pub use sha256::Sha256AcceleratedError;
#[cfg(feature = "cpu")]
pub use sha512_state::Sha512AcceleratedError;

/// Whether the complete portable SHA-256 API is implemented.
pub const SHA256_IMPLEMENTED: bool = true;

/// Whether the complete portable SHA-224 API is implemented.
pub const SHA224_IMPLEMENTED: bool = true;

/// Whether the complete portable SHA-384 API is implemented.
pub const SHA384_IMPLEMENTED: bool = true;

/// Whether the complete portable SHA-512 API is implemented.
pub const SHA512_IMPLEMENTED: bool = true;

/// Whether the complete portable SHA-512/224 API is implemented.
pub const SHA512_224_IMPLEMENTED: bool = true;

/// Whether the complete portable SHA-512/256 API is implemented.
pub const SHA512_256_IMPLEMENTED: bool = true;

/// Computes SHA-224 over one complete byte slice.
///
/// ```
/// let digest = brynja_hash_sha2::sha224(b"abc")?;
/// assert_eq!(
///     digest.as_bytes(),
///     &[
///         0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22,
///         0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2, 0x55, 0xb3,
///         0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7,
///         0xe3, 0x6c, 0x9d, 0xa7,
///     ]
/// );
/// # Ok::<(), brynja_hash_sha2::Sha224Error>(())
/// ```
pub fn sha224(input: &[u8]) -> Result<Sha224Digest, Sha224Error> {
    let mut state = Sha224::new();
    state.update(input)?;
    Ok(state.finalize())
}

/// Computes SHA-256 over one complete byte slice.
///
/// ```
/// let digest = brynja_hash_sha2::sha256(b"abc")?;
/// assert_eq!(
///     digest.as_bytes(),
///     &[
///         0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
///         0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
///         0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
///         0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
///     ]
/// );
/// # Ok::<(), brynja_hash_sha2::Sha256Error>(())
/// ```
pub fn sha256(input: &[u8]) -> Result<Sha256Digest, Sha256Error> {
    let mut state = Sha256::new();
    state.update(input)?;
    Ok(state.finalize())
}

/// Computes SHA-384 over one complete byte slice.
///
/// ```
/// let digest = brynja_hash_sha2::sha384(b"abc")?;
/// assert_eq!(digest.as_bytes().len(), 48);
/// # Ok::<(), brynja_hash_sha2::Sha384Error>(())
/// ```
pub fn sha384(input: &[u8]) -> Result<Sha384Digest, Sha384Error> {
    let mut state = Sha384::new();
    state.update(input)?;
    Ok(state.finalize())
}

/// Computes SHA-512 over one complete byte slice.
///
/// ```
/// let digest = brynja_hash_sha2::sha512(b"abc")?;
/// assert_eq!(digest.as_bytes().len(), 64);
/// # Ok::<(), brynja_hash_sha2::Sha512Error>(())
/// ```
pub fn sha512(input: &[u8]) -> Result<Sha512Digest, Sha512Error> {
    let mut state = Sha512::new();
    state.update(input)?;
    Ok(state.finalize())
}

/// Computes SHA-512/224 over one complete byte slice.
///
/// ```
/// let digest = brynja_hash_sha2::sha512_224(b"abc")?;
/// assert_eq!(digest.as_bytes().len(), 28);
/// # Ok::<(), brynja_hash_sha2::Sha512_224Error>(())
/// ```
pub fn sha512_224(input: &[u8]) -> Result<Sha512_224Digest, Sha512_224Error> {
    let mut state = Sha512_224::new();
    state.update(input)?;
    Ok(state.finalize())
}

/// Computes SHA-512/256 over one complete byte slice.
///
/// ```
/// let digest = brynja_hash_sha2::sha512_256(b"abc")?;
/// assert_eq!(digest.as_bytes().len(), 32);
/// # Ok::<(), brynja_hash_sha2::Sha512_256Error>(())
/// ```
pub fn sha512_256(input: &[u8]) -> Result<Sha512_256Digest, Sha512_256Error> {
    let mut state = Sha512_256::new();
    state.update(input)?;
    Ok(state.finalize())
}

/// Computes SHA-256 with one already-tested accelerated backend.
///
/// The ordinary [`sha256`] API and default feature set remain portable scalar.
#[cfg(feature = "cpu")]
pub fn sha256_with_backend(
    input: &[u8],
    backend: &Sha256BackendSession,
) -> Result<Sha256Digest, Sha256AcceleratedError> {
    let mut state = Sha256::new();
    state.update_with_backend(input, backend)?;
    state.finalize_with_backend(backend)
}

/// Computes SHA-224 with one already-tested SHA-256-family backend.
#[cfg(feature = "cpu")]
pub fn sha224_with_backend(
    input: &[u8],
    backend: &Sha256BackendSession,
) -> Result<Sha224Digest, Sha224AcceleratedError> {
    let mut state = Sha224::new();
    state.update_with_backend(input, backend)?;
    state.finalize_with_backend(backend)
}

/// Computes SHA-384 with one already-tested SHA-512-family backend.
#[cfg(feature = "cpu")]
pub fn sha384_with_backend(
    input: &[u8],
    backend: &Sha512BackendSession,
) -> Result<Sha384Digest, Sha512AcceleratedError> {
    let mut state = Sha384::new();
    state.update_with_backend(input, backend)?;
    state.finalize_with_backend(backend)
}

/// Computes SHA-512 with one already-tested SHA-512-family backend.
#[cfg(feature = "cpu")]
pub fn sha512_with_backend(
    input: &[u8],
    backend: &Sha512BackendSession,
) -> Result<Sha512Digest, Sha512AcceleratedError> {
    let mut state = Sha512::new();
    state.update_with_backend(input, backend)?;
    state.finalize_with_backend(backend)
}

/// Computes SHA-512/224 with one tested SHA-512-family backend.
#[cfg(feature = "cpu")]
pub fn sha512_224_with_backend(
    input: &[u8],
    backend: &Sha512BackendSession,
) -> Result<Sha512_224Digest, Sha512AcceleratedError> {
    let mut state = Sha512_224::new();
    state.update_with_backend(input, backend)?;
    state.finalize_with_backend(backend)
}

/// Computes SHA-512/256 with one tested SHA-512-family backend.
#[cfg(feature = "cpu")]
pub fn sha512_256_with_backend(
    input: &[u8],
    backend: &Sha512BackendSession,
) -> Result<Sha512_256Digest, Sha512AcceleratedError> {
    let mut state = Sha512_256::new();
    state.update_with_backend(input, backend)?;
    state.finalize_with_backend(backend)
}

#[cfg(test)]
mod tests {
    use super::{
        Sha224, Sha224Error, Sha256, Sha256Error, Sha384, Sha384Error, Sha512, Sha512_224,
        Sha512_224Error, Sha512_256, Sha512_256Error, Sha512Error, sha224,
        sha224::{
            checked_message_length as checked_sha224_length,
            padding_block_count as sha224_padding_block_count,
        },
        sha256,
        sha256::{checked_message_length, padding_block_count},
        sha384, sha512, sha512_224, sha512_256,
    };

    #[test]
    fn sha224_checked_length_is_exact_and_fail_closed() {
        assert_eq!(checked_sha224_length(0, 0), Ok(0));
        assert_eq!(
            checked_sha224_length(Sha224::MAX_MESSAGE_BYTES, 0),
            Ok(Sha224::MAX_MESSAGE_BYTES)
        );
        assert_eq!(
            checked_sha224_length(Sha224::MAX_MESSAGE_BYTES, 1),
            Err(Sha224Error::MessageTooLong)
        );
    }

    #[test]
    fn checked_length_is_exact_and_fail_closed() {
        assert_eq!(checked_message_length(0, 0), Ok(0));
        assert_eq!(
            checked_message_length(Sha256::MAX_MESSAGE_BYTES, 0),
            Ok(Sha256::MAX_MESSAGE_BYTES)
        );
        assert_eq!(
            checked_message_length(Sha256::MAX_MESSAGE_BYTES, 1),
            Err(Sha256Error::MessageTooLong)
        );
        assert_eq!(
            checked_message_length(u64::MAX, 1),
            Err(Sha256Error::MessageTooLong)
        );
    }

    #[test]
    fn one_shot_empty_message_is_stable() {
        assert!(sha224(&[]).is_ok());
        assert!(sha256(&[]).is_ok());
        assert!(sha384(&[]).is_ok());
        assert!(sha512(&[]).is_ok());
        assert!(sha512_224(&[]).is_ok());
        assert!(sha512_256(&[]).is_ok());
    }

    #[test]
    fn padding_block_boundaries_are_exact() {
        assert_eq!(sha224_padding_block_count(0), 1);
        assert_eq!(sha224_padding_block_count(55), 1);
        assert_eq!(sha224_padding_block_count(56), 2);
        assert_eq!(sha224_padding_block_count(63), 2);
        assert_eq!(padding_block_count(0), 1);
        assert_eq!(padding_block_count(55), 1);
        assert_eq!(padding_block_count(56), 2);
        assert_eq!(padding_block_count(63), 2);
        assert_eq!(super::sha512_state::padding_block_count(0), 1);
        assert_eq!(super::sha512_state::padding_block_count(111), 1);
        assert_eq!(super::sha512_state::padding_block_count(112), 2);
        assert_eq!(super::sha512_state::padding_block_count(127), 2);
    }

    #[test]
    fn sha512_family_checked_lengths_are_exact() {
        assert_eq!(
            Sha384::new().check_additional_bytes(Sha384::MAX_MESSAGE_BYTES),
            Ok(())
        );
        assert_eq!(
            Sha384::new().check_additional_bytes(Sha384::MAX_MESSAGE_BYTES + 1),
            Err(Sha384Error::MessageTooLong)
        );
        assert_eq!(
            Sha512::new().check_additional_bytes(Sha512::MAX_MESSAGE_BYTES),
            Ok(())
        );
        assert_eq!(
            Sha512::new().check_additional_bytes(Sha512::MAX_MESSAGE_BYTES + 1),
            Err(Sha512Error::MessageTooLong)
        );
        assert_eq!(
            Sha512_224::new().check_additional_bytes(Sha512_224::MAX_MESSAGE_BYTES),
            Ok(())
        );
        assert_eq!(
            Sha512_224::new().check_additional_bytes(Sha512_224::MAX_MESSAGE_BYTES + 1),
            Err(Sha512_224Error::MessageTooLong)
        );
        assert_eq!(
            Sha512_256::new().check_additional_bytes(Sha512_256::MAX_MESSAGE_BYTES),
            Ok(())
        );
        assert_eq!(
            Sha512_256::new().check_additional_bytes(Sha512_256::MAX_MESSAGE_BYTES + 1),
            Err(Sha512_256Error::MessageTooLong)
        );
    }
}

#[cfg(kani)]
mod proofs {
    use super::{
        Sha224, Sha256,
        sha224::{
            checked_message_length as checked_sha224_length,
            padding_block_count as sha224_padding_block_count,
        },
        sha256::checked_message_length,
        sha256::padding_block_count,
        sha512_state::{
            MAX_MESSAGE_BYTES, checked_message_length as checked_sha512_length,
            padding_block_count as sha512_padding_block_count,
        },
    };

    #[kani::proof]
    fn sha224_checked_length_matches_fips_byte_domain() {
        let current: u64 = kani::any();
        let additional: u64 = kani::any();
        let result = checked_sha224_length(current, additional);
        match current.checked_add(additional) {
            Some(total) if total <= Sha224::MAX_MESSAGE_BYTES => {
                assert!(matches!(result, Ok(value) if value == total));
            }
            _ => assert!(result.is_err()),
        }
    }

    #[kani::proof]
    fn sha224_padding_uses_one_or_two_blocks_at_exact_boundary() {
        let buffered: usize = kani::any();
        kani::assume(buffered < 64);
        let blocks = sha224_padding_block_count(buffered);
        assert!(blocks == 1 || blocks == 2);
        assert_eq!(blocks == 1, buffered <= 55);
    }

    #[kani::proof]
    fn sha256_checked_length_matches_fips_byte_domain() {
        let current: u64 = kani::any();
        let additional: u64 = kani::any();
        let result = checked_message_length(current, additional);
        match current.checked_add(additional) {
            Some(total) if total <= Sha256::MAX_MESSAGE_BYTES => {
                assert!(matches!(result, Ok(value) if value == total));
            }
            _ => assert!(result.is_err()),
        }
    }

    #[kani::proof]
    fn sha256_padding_uses_one_or_two_blocks_at_exact_boundary() {
        let buffered: usize = kani::any();
        kani::assume(buffered < 64);
        let blocks = padding_block_count(buffered);
        assert!(blocks == 1 || blocks == 2);
        assert_eq!(blocks == 1, buffered <= 55);
    }

    #[kani::proof]
    fn sha512_family_checked_length_matches_fips_byte_domain() {
        let current: u128 = kani::any();
        let additional: u128 = kani::any();
        let result = checked_sha512_length(current, additional);
        match current.checked_add(additional) {
            Some(total) if total <= MAX_MESSAGE_BYTES => {
                assert!(matches!(result, Ok(value) if value == total));
            }
            _ => assert!(result.is_err()),
        }
    }

    #[kani::proof]
    fn sha512_family_padding_uses_one_or_two_blocks_at_exact_boundary() {
        let buffered: usize = kani::any();
        kani::assume(buffered < 128);
        let blocks = sha512_padding_block_count(buffered);
        assert!(blocks == 1 || blocks == 2);
        assert_eq!(blocks == 1, buffered <= 111);
    }
}
