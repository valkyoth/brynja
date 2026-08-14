//! Complete portable SHA-256 for Brynja.
//!
//! The byte-oriented one-shot and streaming APIs implement FIPS 180-4
//! SHA-256 without allocation, low-level code, I/O, global mutable state, or a
//! hardware requirement. SHA-224, SHA-384, and SHA-512 are not implemented by
//! this release.

#![no_std]

mod compress;
mod digest;
mod error;
mod sha256;

pub use brynja_hash_core::{FixedOutput, Update};
pub use digest::Sha256Digest;
pub use error::Sha256Error;
pub use sha256::Sha256;

/// Whether the complete portable SHA-256 API is implemented.
pub const SHA256_IMPLEMENTED: bool = true;

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

#[cfg(test)]
mod tests {
    use super::{
        Sha256, Sha256Error, sha256,
        sha256::{checked_message_length, padding_block_count},
    };

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
        assert!(sha256(&[]).is_ok());
    }

    #[test]
    fn padding_block_boundaries_are_exact() {
        assert_eq!(padding_block_count(0), 1);
        assert_eq!(padding_block_count(55), 1);
        assert_eq!(padding_block_count(56), 2);
        assert_eq!(padding_block_count(63), 2);
    }
}

#[cfg(kani)]
mod proofs {
    use super::{Sha256, sha256::checked_message_length, sha256::padding_block_count};

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
}
