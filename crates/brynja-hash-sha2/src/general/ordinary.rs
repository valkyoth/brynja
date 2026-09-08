use super::{Sha512TBits, Sha512TDigest, Sha512TError};
use crate::{BitString, sha512_state::Sha512State};

/// Portable general SHA-512/t for public data. Internal memory is not erased.
/// Use `HardenedSha512T` for confidential input. Default operations select no CPU
/// route; explicit ordinary CPU methods require the additional `cpu` feature.
pub struct Sha512T {
    pub(super) parameter: Sha512TBits,
    pub(super) state: Sha512State,
}

impl Sha512T {
    /// Largest valid bit length (the FIPS domain is strictly below 2^128).
    pub const MAX_MESSAGE_BITS: u128 = u128::MAX;
    /// Largest complete-byte message length.
    pub const MAX_MESSAGE_BYTES: u128 = u128::MAX / 8;
    /// Derives this identity's IV using one fixed-work public compression.
    #[must_use]
    pub fn new(parameter: Sha512TBits) -> Self {
        Self {
            parameter,
            state: Sha512State::new(parameter.initial_words()),
        }
    }
    /// Exact public algorithm parameter.
    #[must_use]
    pub const fn parameter(&self) -> Sha512TBits {
        self.parameter
    }
    /// Number of complete bytes accepted so far.
    #[must_use]
    pub const fn message_bytes(&self) -> u128 {
        self.state.message_bytes()
    }
    /// Rejects impossible byte counts without changing state.
    pub fn check_additional_bytes(&self, count: u128) -> Result<(), Sha512TError> {
        self.state
            .check_additional_bytes(count)
            .map_err(|_| Sha512TError::MessageTooLong)
    }
    /// Rejects impossible bit counts without changing state.
    pub fn check_additional_bits(&self, count: u128) -> Result<(), Sha512TError> {
        self.state
            .check_additional_bits(count)
            .map_err(|_| Sha512TError::MessageTooLong)
    }
    /// Absorbs complete bytes; rejection preserves the prior state.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Sha512TError> {
        self.state
            .update(input)
            .map_err(|_| Sha512TError::MessageTooLong)
    }
    /// Consumes the state and returns the exact canonical public t-bit digest.
    pub fn finalize(self) -> Result<Sha512TDigest, Sha512TError> {
        render(self.parameter, self.state.finalize())
    }
    /// Consumes the state, appending a final canonical MSB-first bit string.
    pub fn finalize_bits(self, input: BitString<'_>) -> Result<Sha512TDigest, Sha512TError> {
        render(
            self.parameter,
            self.state
                .finalize_bits(input)
                .map_err(|_| Sha512TError::MessageTooLong)?,
        )
    }
}

pub(super) fn render(
    parameter: Sha512TBits,
    words: [u64; 8],
) -> Result<Sha512TDigest, Sha512TError> {
    let mut bytes = [0; 64];
    for (slot, word) in bytes.chunks_exact_mut(8).zip(words) {
        slot.copy_from_slice(&word.to_be_bytes());
    }
    Sha512TDigest::computed(parameter, &bytes)
}

/// Synchronously hashes public bytes in linear time and fixed storage.
pub fn sha512_t(parameter: Sha512TBits, input: &[u8]) -> Result<Sha512TDigest, Sha512TError> {
    let mut state = Sha512T::new(parameter);
    state.update(input)?;
    state.finalize()
}
/// Synchronously hashes a canonical public MSB-first arbitrary-bit message.
pub fn sha512_t_bits(
    parameter: Sha512TBits,
    input: BitString<'_>,
) -> Result<Sha512TDigest, Sha512TError> {
    Sha512T::new(parameter).finalize_bits(input)
}
