use brynja_hash_core::{FixedOutput, Update};

use crate::{BitString, Sha512_224Digest, Sha512_224Error, sha512_state, sha512_t};

#[cfg(feature = "cpu")]
use brynja_crypto_cpu::Sha512BackendSession;

/// Portable streaming SHA-512/224 state.
///
/// SHA-512/224 has its own FIPS 180-4 derived initial value; it is not ordinary
/// SHA-512 followed by truncation. Finalization consumes the state. This type
/// intentionally does not implement `Clone`, `Copy`, `Debug`, or formatting
/// traits. Its ordinary unkeyed state is not promised to be erased after use.
pub struct Sha512_224 {
    inner: sha512_state::Sha512State,
}

impl Sha512_224 {
    /// Maximum arbitrary-bit message length admitted by FIPS 180-4.
    pub const MAX_MESSAGE_BITS: u128 = sha512_state::MAX_MESSAGE_BITS;

    /// Maximum byte-oriented message length admitted by FIPS 180-4.
    pub const MAX_MESSAGE_BYTES: u128 = sha512_state::MAX_MESSAGE_BYTES;

    /// Creates an empty portable SHA-512/224 state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: sha512_state::Sha512State::new(sha512_t::SHA512_224_INITIAL_STATE),
        }
    }

    /// Returns the number of message bytes accepted so far.
    #[must_use]
    pub const fn message_bytes(&self) -> u128 {
        self.inner.message_bytes()
    }

    /// Returns the byte-aligned number of message bits accepted so far.
    #[must_use]
    pub const fn message_bits(&self) -> u128 {
        self.inner.message_bits()
    }

    /// Checks an update length without changing this state.
    pub fn check_additional_bytes(&self, additional_bytes: u128) -> Result<(), Sha512_224Error> {
        self.inner
            .check_additional_bytes(additional_bytes)
            .map_err(|_| Sha512_224Error::MessageTooLong)
    }

    /// Checks an exact bit count without changing this state.
    pub fn check_additional_bits(&self, additional_bits: u128) -> Result<(), Sha512_224Error> {
        self.inner
            .check_additional_bits(additional_bits)
            .map_err(|_| Sha512_224Error::MessageTooLong)
    }

    /// Absorbs all input or rejects it before changing observable state.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Sha512_224Error> {
        self.inner
            .update(input)
            .map_err(|_| Sha512_224Error::MessageTooLong)
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

    /// Consumes the state and returns the exact SHA-512/224 digest.
    #[must_use]
    pub fn finalize(self) -> Sha512_224Digest {
        Sha512_224Digest::from_bytes(sha512_t::leftmost_bytes(self.inner.finalize()))
    }

    /// Consumes the state after absorbing one final canonical bit string.
    pub fn finalize_bits(self, input: BitString<'_>) -> Result<Sha512_224Digest, Sha512_224Error> {
        self.inner
            .finalize_bits(input)
            .map(sha512_t::leftmost_bytes)
            .map(Sha512_224Digest::from_bytes)
            .map_err(|_| Sha512_224Error::MessageTooLong)
    }

    #[cfg(feature = "cpu")]
    /// Consumes the state and finalizes through one tested backend.
    pub fn finalize_with_backend(
        self,
        backend: &Sha512BackendSession,
    ) -> Result<Sha512_224Digest, sha512_state::Sha512AcceleratedError> {
        self.inner
            .finalize_with_backend(backend)
            .map(sha512_t::leftmost_bytes)
            .map(Sha512_224Digest::from_bytes)
    }

    #[cfg(feature = "cpu")]
    /// Consumes the state after a final bit string through one tested backend.
    pub fn finalize_bits_with_backend(
        self,
        input: BitString<'_>,
        backend: &Sha512BackendSession,
    ) -> Result<Sha512_224Digest, sha512_state::Sha512AcceleratedError> {
        self.inner
            .finalize_bits_with_backend(input, backend)
            .map(sha512_t::leftmost_bytes)
            .map(Sha512_224Digest::from_bytes)
    }
}

impl Default for Sha512_224 {
    fn default() -> Self {
        Self::new()
    }
}

impl Update for Sha512_224 {
    type Error = Sha512_224Error;

    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        Self::update(self, input)
    }
}

impl FixedOutput for Sha512_224 {
    type Output = Sha512_224Digest;

    fn finalize(self) -> Self::Output {
        Self::finalize(self)
    }
}
