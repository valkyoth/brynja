use crate::{
    BitString, Sha224, Sha224Digest, Sha224Error, Sha256, Sha256Digest, Sha256Error, Sha384,
    Sha384Digest, Sha384Error, Sha512, Sha512_224, Sha512_224Digest, Sha512_224Error, Sha512_256,
    Sha512_256Digest, Sha512_256Error, Sha512Digest, Sha512Error,
};

#[cfg(feature = "cpu")]
use crate::{Sha224AcceleratedError, Sha256AcceleratedError, Sha512AcceleratedError};
#[cfg(feature = "cpu")]
use brynja_crypto_cpu::{Sha256BackendSession, Sha512BackendSession};

/// Computes SHA-224 over one canonical arbitrary-bit message.
pub fn sha224_bits(input: BitString<'_>) -> Result<Sha224Digest, Sha224Error> {
    Sha224::new().finalize_bits(input)
}

/// Computes SHA-256 over one canonical arbitrary-bit message.
///
/// ```
/// use brynja_hash_sha2::{BitString, sha256_bits};
///
/// // The three message bits are `011`; unused low storage bits are zero.
/// let digest = BitString::new(&[0b0110_0000], 3)
///     .ok()
///     .and_then(|input| sha256_bits(input).ok());
/// assert_eq!(
///     digest.as_ref().map(|value| &value.as_bytes()[..4]),
///     Some(&[0x1f, 0x77, 0x94, 0xd4][..]),
/// );
/// ```
pub fn sha256_bits(input: BitString<'_>) -> Result<Sha256Digest, Sha256Error> {
    Sha256::new().finalize_bits(input)
}

/// Computes SHA-384 over one canonical arbitrary-bit message.
pub fn sha384_bits(input: BitString<'_>) -> Result<Sha384Digest, Sha384Error> {
    Sha384::new().finalize_bits(input)
}

/// Computes SHA-512 over one canonical arbitrary-bit message.
pub fn sha512_bits(input: BitString<'_>) -> Result<Sha512Digest, Sha512Error> {
    Sha512::new().finalize_bits(input)
}

/// Computes SHA-512/224 over one canonical arbitrary-bit message.
pub fn sha512_224_bits(input: BitString<'_>) -> Result<Sha512_224Digest, Sha512_224Error> {
    Sha512_224::new().finalize_bits(input)
}

/// Computes SHA-512/256 over one canonical arbitrary-bit message.
pub fn sha512_256_bits(input: BitString<'_>) -> Result<Sha512_256Digest, Sha512_256Error> {
    Sha512_256::new().finalize_bits(input)
}

/// Computes bit-oriented SHA-224 through one tested accelerated backend.
#[cfg(feature = "cpu")]
pub fn sha224_bits_with_backend(
    input: BitString<'_>,
    backend: &Sha256BackendSession,
) -> Result<Sha224Digest, Sha224AcceleratedError> {
    Sha224::new().finalize_bits_with_backend(input, backend)
}

/// Computes bit-oriented SHA-256 through one tested accelerated backend.
#[cfg(feature = "cpu")]
pub fn sha256_bits_with_backend(
    input: BitString<'_>,
    backend: &Sha256BackendSession,
) -> Result<Sha256Digest, Sha256AcceleratedError> {
    Sha256::new().finalize_bits_with_backend(input, backend)
}

/// Computes bit-oriented SHA-384 through one tested accelerated backend.
#[cfg(feature = "cpu")]
pub fn sha384_bits_with_backend(
    input: BitString<'_>,
    backend: &Sha512BackendSession,
) -> Result<Sha384Digest, Sha512AcceleratedError> {
    Sha384::new().finalize_bits_with_backend(input, backend)
}

/// Computes bit-oriented SHA-512 through one tested accelerated backend.
#[cfg(feature = "cpu")]
pub fn sha512_bits_with_backend(
    input: BitString<'_>,
    backend: &Sha512BackendSession,
) -> Result<Sha512Digest, Sha512AcceleratedError> {
    Sha512::new().finalize_bits_with_backend(input, backend)
}

/// Computes bit-oriented SHA-512/224 through one tested accelerated backend.
#[cfg(feature = "cpu")]
pub fn sha512_224_bits_with_backend(
    input: BitString<'_>,
    backend: &Sha512BackendSession,
) -> Result<Sha512_224Digest, Sha512AcceleratedError> {
    Sha512_224::new().finalize_bits_with_backend(input, backend)
}

/// Computes bit-oriented SHA-512/256 through one tested accelerated backend.
#[cfg(feature = "cpu")]
pub fn sha512_256_bits_with_backend(
    input: BitString<'_>,
    backend: &Sha512BackendSession,
) -> Result<Sha512_256Digest, Sha512AcceleratedError> {
    Sha512_256::new().finalize_bits_with_backend(input, backend)
}
