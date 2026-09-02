use brynja_hash_core::{FixedOutput, Update};

use crate::{BitString, Sha512Digest, Sha512Error, sha512_state};

#[cfg(feature = "cpu")]
use brynja_crypto_cpu::Sha512BackendSession;

pub(crate) const INITIAL_STATE: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

/// Portable streaming SHA-512 state.
///
/// Finalization consumes the state. This type intentionally does not implement
/// `Clone`, `Copy`, `Debug`, or formatting traits. Its ordinary unkeyed state
/// is not promised to be erased after use; secret-bearing constructions need a
/// separate hardened owner.
pub struct Sha512 {
    inner: sha512_state::Sha512State,
}

impl Sha512 {
    /// Maximum arbitrary-bit message length admitted by FIPS 180-4.
    pub const MAX_MESSAGE_BITS: u128 = sha512_state::MAX_MESSAGE_BITS;

    /// Maximum byte-oriented message length admitted by FIPS 180-4.
    pub const MAX_MESSAGE_BYTES: u128 = sha512_state::MAX_MESSAGE_BYTES;

    /// Creates an empty portable SHA-512 state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: sha512_state::Sha512State::new(INITIAL_STATE),
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
    pub fn check_additional_bytes(&self, additional_bytes: u128) -> Result<(), Sha512Error> {
        self.inner
            .check_additional_bytes(additional_bytes)
            .map_err(|_| Sha512Error::MessageTooLong)
    }

    /// Checks an exact bit count without changing this state.
    pub fn check_additional_bits(&self, additional_bits: u128) -> Result<(), Sha512Error> {
        self.inner
            .check_additional_bits(additional_bits)
            .map_err(|_| Sha512Error::MessageTooLong)
    }

    /// Absorbs all input or rejects it before changing observable state.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Sha512Error> {
        self.inner
            .update(input)
            .map_err(|_| Sha512Error::MessageTooLong)
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

    /// Consumes the state and returns the exact SHA-512 digest.
    #[must_use]
    pub fn finalize(self) -> Sha512Digest {
        digest(self.inner.finalize())
    }

    /// Consumes the state after absorbing one final canonical bit string.
    pub fn finalize_bits(self, input: BitString<'_>) -> Result<Sha512Digest, Sha512Error> {
        self.inner
            .finalize_bits(input)
            .map(digest)
            .map_err(|_| Sha512Error::MessageTooLong)
    }

    #[cfg(feature = "cpu")]
    /// Consumes the state and finalizes through one tested backend.
    pub fn finalize_with_backend(
        self,
        backend: &Sha512BackendSession,
    ) -> Result<Sha512Digest, sha512_state::Sha512AcceleratedError> {
        self.inner.finalize_with_backend(backend).map(digest)
    }

    #[cfg(feature = "cpu")]
    /// Consumes the state after a final bit string through one tested backend.
    pub fn finalize_bits_with_backend(
        self,
        input: BitString<'_>,
        backend: &Sha512BackendSession,
    ) -> Result<Sha512Digest, sha512_state::Sha512AcceleratedError> {
        self.inner
            .finalize_bits_with_backend(input, backend)
            .map(digest)
    }
}

fn digest(state: [u64; 8]) -> Sha512Digest {
    let mut output = [0_u8; Sha512Digest::LENGTH];
    for (bytes, word) in output.chunks_exact_mut(8).zip(state.iter()) {
        for (target, byte) in bytes.iter_mut().zip(word.to_be_bytes()) {
            *target = byte;
        }
    }
    Sha512Digest::from_bytes(output)
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Update for Sha512 {
    type Error = Sha512Error;

    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        Self::update(self, input)
    }
}

impl FixedOutput for Sha512 {
    type Output = Sha512Digest;

    fn finalize(self) -> Self::Output {
        Self::finalize(self)
    }
}
