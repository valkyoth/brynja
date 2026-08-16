use brynja_hash_core::{FixedOutput, Update};

use crate::{Sha512_256Digest, Sha512_256Error, sha512_state, sha512_t};

#[cfg(feature = "cpu")]
use brynja_crypto_cpu::Sha512BackendSession;

/// Portable streaming SHA-512/256 state.
///
/// SHA-512/256 has its own FIPS 180-4 derived initial value; it is not ordinary
/// SHA-512 followed by truncation. Finalization consumes the state. This type
/// intentionally does not implement `Clone`, `Copy`, `Debug`, or formatting
/// traits. Its ordinary unkeyed state is not promised to be erased after use.
pub struct Sha512_256 {
    inner: sha512_state::Sha512State,
}

impl Sha512_256 {
    /// Maximum byte-oriented message length admitted by FIPS 180-4.
    pub const MAX_MESSAGE_BYTES: u128 = sha512_state::MAX_MESSAGE_BYTES;

    /// Creates an empty portable SHA-512/256 state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: sha512_state::Sha512State::new(sha512_t::SHA512_256_INITIAL_STATE),
        }
    }

    /// Returns the number of message bytes accepted so far.
    #[must_use]
    pub const fn message_bytes(&self) -> u128 {
        self.inner.message_bytes()
    }

    /// Checks an update length without changing this state.
    pub fn check_additional_bytes(&self, additional_bytes: u128) -> Result<(), Sha512_256Error> {
        self.inner
            .check_additional_bytes(additional_bytes)
            .map_err(|_| Sha512_256Error::MessageTooLong)
    }

    /// Absorbs all input or rejects it before changing observable state.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Sha512_256Error> {
        self.inner
            .update(input)
            .map_err(|_| Sha512_256Error::MessageTooLong)
    }

    #[cfg(feature = "cpu")]
    /// Absorbs input through one tested SHA-512-family backend.
    pub fn update_with_backend(
        &mut self,
        input: &[u8],
        backend: &Sha512BackendSession,
    ) -> Result<(), sha512_state::Sha512AcceleratedError> {
        self.inner.update_with_backend(input, backend)
    }

    /// Consumes the state and returns the exact SHA-512/256 digest.
    #[must_use]
    pub fn finalize(self) -> Sha512_256Digest {
        Sha512_256Digest::from_bytes(sha512_t::leftmost_bytes(self.inner.finalize()))
    }

    #[cfg(feature = "cpu")]
    /// Consumes the state and finalizes through one tested backend.
    pub fn finalize_with_backend(
        self,
        backend: &Sha512BackendSession,
    ) -> Result<Sha512_256Digest, sha512_state::Sha512AcceleratedError> {
        self.inner
            .finalize_with_backend(backend)
            .map(sha512_t::leftmost_bytes)
            .map(Sha512_256Digest::from_bytes)
    }
}

impl Default for Sha512_256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Update for Sha512_256 {
    type Error = Sha512_256Error;

    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        Self::update(self, input)
    }
}

impl FixedOutput for Sha512_256 {
    type Output = Sha512_256Digest;

    fn finalize(self) -> Self::Output {
        Self::finalize(self)
    }
}
