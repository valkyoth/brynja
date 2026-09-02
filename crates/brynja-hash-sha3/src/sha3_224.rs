use brynja_hash_core::{FixedOutput, Update};

use crate::{Fips202BitString, Sha3_224Digest, Sha3_224Error, sponge::Sponge};

const RATE_BYTES: usize = 144;

/// Portable streaming SHA3-224 state.
///
/// Finalization consumes the state. This type intentionally does not implement
/// `Clone`, `Copy`, `Debug`, or formatting traits. Its ordinary unkeyed state
/// is not promised to be erased after use; secret-bearing constructions need a
/// separate hardened owner.
pub struct Sha3_224(Sponge<RATE_BYTES>);

impl Sha3_224 {
    /// Maximum byte count representable by this implementation's counter.
    pub const MAX_MESSAGE_BYTES: u128 = Sponge::<RATE_BYTES>::MAX_MESSAGE_BYTES;

    /// Creates an empty portable SHA3-224 state.
    #[must_use]
    pub const fn new() -> Self {
        Self(Sponge::new())
    }

    /// Returns the number of message bytes accepted so far.
    #[must_use]
    pub const fn message_bytes(&self) -> u128 {
        self.0.message_bytes()
    }

    /// Checks an update length without changing this state.
    pub fn check_additional_bytes(&self, additional: u128) -> Result<(), Sha3_224Error> {
        self.0
            .check_additional_bytes(additional)
            .map_err(|()| Sha3_224Error::MessageTooLong)
    }

    /// Checks an exact bit count without changing this state.
    pub fn check_additional_bits(&self, additional: u128) -> Result<(), Sha3_224Error> {
        self.0
            .check_additional_bits(additional)
            .map_err(|()| Sha3_224Error::MessageTooLong)
    }

    /// Absorbs all input or rejects it before changing observable state.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Sha3_224Error> {
        self.0
            .update(input)
            .map_err(|()| Sha3_224Error::MessageTooLong)
    }

    /// Consumes the state and returns the exact SHA3-224 digest.
    #[must_use]
    pub fn finalize(self) -> Sha3_224Digest {
        Sha3_224Digest::from_bytes(self.0.finalize())
    }

    /// Consumes the state after absorbing one final canonical bit string.
    pub fn finalize_bits(
        mut self,
        input: Fips202BitString<'_>,
    ) -> Result<Sha3_224Digest, Sha3_224Error> {
        let bits = u128::try_from(input.bit_len()).map_err(|_| Sha3_224Error::MessageTooLong)?;
        self.0
            .check_additional_bits(bits)
            .map_err(|()| Sha3_224Error::MessageTooLong)?;
        let (complete, partial) = input.split();
        self.update(complete)?;
        Ok(Sha3_224Digest::from_bytes(self.0.finalize_bits(partial)))
    }
}

impl Default for Sha3_224 {
    fn default() -> Self {
        Self::new()
    }
}

impl Update for Sha3_224 {
    type Error = Sha3_224Error;

    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        Self::update(self, input)
    }
}

impl FixedOutput for Sha3_224 {
    type Output = Sha3_224Digest;

    fn finalize(self) -> Self::Output {
        Self::finalize(self)
    }
}
