use brynja_hash_sha2::{HardenedSha512T, Sha512TBits, Sha512TError};

use crate::{Algorithm, Error, Sha2BitString, algorithms::sealed};

/// General SHA-512/t HMAC identity, distinct from named SHA-512/224 and /256.
///
/// Construction accepts 128..=511 except 384. Smaller mathematical parameters
/// are rejected by the HMAC tag-strength policy, even though the hash supports
/// them. This is not a claim that arbitrary t is FIPS-approved.
///
/// Full tags contain exactly T bits in ceil(T/8) bytes, with unused low bits
/// zero. Verification rejects noncanonical unused bits by comparing them too.
/// `with_tag_length` selects a whole-byte prefix no longer than floor(T/8);
/// `new` selects the exact full digest. Keys remain byte strings.
///
/// ```
/// use brynja_mac_hmac::{Hmac, Sha512T};
/// let mut output = [0; 17];
/// let tag = Hmac::<Sha512T<129>>::authenticate(b"example key", b"message", &mut output)?;
/// assert_eq!(tag.bit_len(), 129);
/// assert_eq!(tag.as_bytes()[16] & 0x7f, 0);
/// # Ok::<(), brynja_mac_hmac::Error>(())
/// ```
pub enum Sha512T<const T: u16> {}

impl<const T: u16> Algorithm for Sha512T<T> {
    const BLOCK_BYTES: usize = 128;
    const TAG_BYTES: usize = (T as usize).div_ceil(8);
    const TAG_BITS: usize = T as usize;
}

fn error(error: Sha512TError) -> Error {
    match error {
        Sha512TError::InvalidParameter => Error::AlgorithmParameter,
        Sha512TError::MessageTooLong => Error::MessageTooLong,
        _ => Error::SecretMemory,
    }
}

impl<const T: u16> sealed::Hash for Sha512T<T> {
    type State = HardenedSha512T;
    type FinalInput<'a> = Sha2BitString<'a>;

    fn validate() -> Result<(), Error> {
        if T < 128 {
            return Err(Error::AlgorithmParameter);
        }
        Sha512TBits::new(T).map(|_| ()).map_err(error)
    }

    fn start() -> Result<Self::State, Error> {
        Self::validate()?;
        Ok(HardenedSha512T::new(Sha512TBits::new(T).map_err(error)?))
    }

    fn update(state: &mut Self::State, input: &[u8]) -> Result<(), Error> {
        state.update(input).map_err(error)
    }

    fn finish(
        state: Self::State,
        output: &mut [u8],
        consume: impl FnOnce(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let digest = state.finalize_secret(output).map_err(error)?;
        consume(digest.as_bytes())
    }

    fn finish_bits(
        state: Self::State,
        input: Self::FinalInput<'_>,
        output: &mut [u8],
        consume: impl FnOnce(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let digest = state.finalize_bits_secret(input, output).map_err(error)?;
        consume(digest.as_bytes())
    }

    fn finish_outer(
        state: Self::State,
        digest: &[u8],
        output: &mut [u8],
        consume: impl FnOnce(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        // Do not append the unused low storage bits to the outer message.
        // Long-key normalization instead zero-extends to the full pad block.
        let valid = u8::try_from(if T.is_multiple_of(8) { 8 } else { T % 8 })
            .map_err(|_| Error::AlgorithmParameter)?;
        let input = Sha2BitString::new(digest, valid).map_err(|_| Error::SecretMemory)?;
        Self::finish_bits(state, input, output, consume)
    }
}
