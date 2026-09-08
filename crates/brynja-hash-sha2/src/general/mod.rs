//! General SHA-512/t public parameter and digest values, not a hash engine.

mod digest;
mod iv;
mod parameter;

pub use digest::Sha512TDigest;
pub use parameter::Sha512TBits;

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
}
