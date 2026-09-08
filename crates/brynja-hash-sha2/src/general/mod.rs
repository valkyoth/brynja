//! Portable general SHA-512/t with distinct public and secret ownership.

mod digest;
mod hardened;
mod iv;
mod one_shot;
mod ordinary;
mod parameter;
mod secret;

pub use digest::Sha512TDigest;
pub use hardened::HardenedSha512T;
pub use one_shot::{
    hardened_sha512_t_bits_public, hardened_sha512_t_bits_secret, hardened_sha512_t_public,
    hardened_sha512_t_secret,
};
pub use ordinary::{Sha512T, sha512_t, sha512_t_bits};
pub use parameter::Sha512TBits;
pub use secret::Sha512TSecretDigest;

/// A rejected general SHA-512/t public descriptor or digest representation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Sha512TError {
    /// t must be in 1..=511, excluding 384.
    InvalidParameter,
    /// The label destination is too short or the digest length is not exact.
    OutputLength,
    /// The unused low bits in a public digest's last byte are not zero.
    NonCanonicalOutput,
    /// The complete message would contain 2^128 or more bits.
    MessageTooLong,
    /// Mandatory secret-region initialization or clearing failed.
    SecretMemory,
}

impl From<brynja_core::SecretMemoryError> for Sha512TError {
    fn from(_: brynja_core::SecretMemoryError) -> Self {
        Self::SecretMemory
    }
}
