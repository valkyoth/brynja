use brynja_hash_core::{FixedOutput, Update};

use crate::{BitString, Sha384Digest, Sha384Error, sha512_state};

#[cfg(feature = "cpu")]
use brynja_crypto_cpu::Sha512BackendSession;

const INITIAL_STATE: [u64; 8] = [
    0xcbbb_9d5d_c105_9ed8,
    0x629a_292a_367c_d507,
    0x9159_015a_3070_dd17,
    0x152f_ecd8_f70e_5939,
    0x6733_2667_ffc0_0b31,
    0x8eb4_4a87_6858_1511,
    0xdb0c_2e0d_64f9_8fa7,
    0x47b5_481d_befa_4fa4,
];

/// Portable streaming SHA-384 state.
///
/// Finalization consumes the state. This type intentionally does not implement
/// `Clone`, `Copy`, `Debug`, or formatting traits. Its ordinary unkeyed state
/// is not promised to be erased after use; secret-bearing constructions need a
/// separate hardened owner.
pub struct Sha384 {
    inner: sha512_state::Sha512State,
}

impl Sha384 {
    /// Maximum arbitrary-bit message length admitted by FIPS 180-4.
    pub const MAX_MESSAGE_BITS: u128 = sha512_state::MAX_MESSAGE_BITS;

    /// Maximum byte-oriented message length admitted by FIPS 180-4.
    pub const MAX_MESSAGE_BYTES: u128 = sha512_state::MAX_MESSAGE_BYTES;

    /// Creates an empty portable SHA-384 state.
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
    pub fn check_additional_bytes(&self, additional_bytes: u128) -> Result<(), Sha384Error> {
        self.inner
            .check_additional_bytes(additional_bytes)
            .map_err(|_| Sha384Error::MessageTooLong)
    }

    /// Checks an exact bit count without changing this state.
    pub fn check_additional_bits(&self, additional_bits: u128) -> Result<(), Sha384Error> {
        self.inner
            .check_additional_bits(additional_bits)
            .map_err(|_| Sha384Error::MessageTooLong)
    }

    /// Absorbs all input or rejects it before changing observable state.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Sha384Error> {
        self.inner
            .update(input)
            .map_err(|_| Sha384Error::MessageTooLong)
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

    /// Consumes the state and returns the exact SHA-384 digest.
    #[must_use]
    pub fn finalize(self) -> Sha384Digest {
        digest(self.inner.finalize())
    }

    /// Consumes the state after absorbing one final canonical bit string.
    pub fn finalize_bits(self, input: BitString<'_>) -> Result<Sha384Digest, Sha384Error> {
        self.inner
            .finalize_bits(input)
            .map(digest)
            .map_err(|_| Sha384Error::MessageTooLong)
    }

    #[cfg(feature = "cpu")]
    /// Consumes the state and finalizes through one tested backend.
    pub fn finalize_with_backend(
        self,
        backend: &Sha512BackendSession,
    ) -> Result<Sha384Digest, sha512_state::Sha512AcceleratedError> {
        self.inner.finalize_with_backend(backend).map(digest)
    }

    #[cfg(feature = "cpu")]
    /// Consumes the state after a final bit string through one tested backend.
    pub fn finalize_bits_with_backend(
        self,
        input: BitString<'_>,
        backend: &Sha512BackendSession,
    ) -> Result<Sha384Digest, sha512_state::Sha512AcceleratedError> {
        self.inner
            .finalize_bits_with_backend(input, backend)
            .map(digest)
    }
}

fn digest(state: [u64; 8]) -> Sha384Digest {
    let mut output = [0_u8; Sha384Digest::LENGTH];
    for (bytes, word) in output.chunks_exact_mut(8).zip(state.iter().take(6)) {
        for (target, byte) in bytes.iter_mut().zip(word.to_be_bytes()) {
            *target = byte;
        }
    }
    Sha384Digest::from_bytes(output)
}

impl Default for Sha384 {
    fn default() -> Self {
        Self::new()
    }
}

impl Update for Sha384 {
    type Error = Sha384Error;

    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        Self::update(self, input)
    }
}

impl FixedOutput for Sha384 {
    type Output = Sha384Digest;

    fn finalize(self) -> Self::Output {
        Self::finalize(self)
    }
}
