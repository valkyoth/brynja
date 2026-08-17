use brynja_hash_core::{FixedOutput, Update};

use crate::{Sha3_256Digest, Sha3_256Error, sponge::Sponge};

const RATE_BYTES: usize = 136;

/// Portable streaming SHA3-256 state.
///
/// Finalization consumes the state. This type intentionally does not implement
/// `Clone`, `Copy`, `Debug`, or formatting traits. Its ordinary unkeyed state
/// is not promised to be erased after use; secret-bearing constructions need a
/// separate hardened owner.
pub struct Sha3_256(Sponge<RATE_BYTES>);

impl Sha3_256 {
    /// Maximum byte count representable by this implementation's counter.
    pub const MAX_MESSAGE_BYTES: u128 = Sponge::<RATE_BYTES>::MAX_MESSAGE_BYTES;

    /// Creates an empty portable SHA3-256 state.
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
    pub fn check_additional_bytes(&self, additional: u128) -> Result<(), Sha3_256Error> {
        self.0
            .check_additional_bytes(additional)
            .map_err(|()| Sha3_256Error::MessageTooLong)
    }

    /// Absorbs all input or rejects it before changing observable state.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Sha3_256Error> {
        self.0
            .update(input)
            .map_err(|()| Sha3_256Error::MessageTooLong)
    }

    /// Consumes the state and returns the exact SHA3-256 digest.
    #[must_use]
    pub fn finalize(self) -> Sha3_256Digest {
        Sha3_256Digest::from_bytes(self.0.finalize())
    }
}

impl Default for Sha3_256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Update for Sha3_256 {
    type Error = Sha3_256Error;

    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        Self::update(self, input)
    }
}

impl FixedOutput for Sha3_256 {
    type Output = Sha3_256Digest;

    fn finalize(self) -> Self::Output {
        Self::finalize(self)
    }
}
