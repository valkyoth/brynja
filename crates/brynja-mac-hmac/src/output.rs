use core::marker::PhantomData;

use brynja_core::{Choice, OwnedSecretRegion};

use crate::Algorithm;

/// Public authenticator bound to its HMAC algorithm, not an unkeyed digest.
#[must_use = "the authenticator should be consumed"]
pub struct Tag<'a, A: Algorithm> {
    bytes: &'a [u8],
    algorithm: PhantomData<A>,
}

impl<'a, A: Algorithm> Tag<'a, A> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            algorithm: PhantomData,
        }
    }

    /// Borrows the intentionally public tag for transport.
    pub const fn as_bytes(&self) -> &[u8] {
        self.bytes
    }
}

/// Clearing ownership of a tag retained as secret derived material.
#[must_use = "keep ownership live until the secret is no longer required"]
pub struct SecretTag<'a, A: Algorithm> {
    region: OwnedSecretRegion<'a>,
    algorithm: PhantomData<A>,
}

impl<'a, A: Algorithm> SecretTag<'a, A> {
    pub(crate) const fn new(region: OwnedSecretRegion<'a>) -> Self {
        Self {
            region,
            algorithm: PhantomData,
        }
    }

    /// Borrows secret bytes; application copies need their own cleanup policy.
    pub fn expose(&self) -> &[u8] {
        self.region.expose()
    }
}

/// Explicitly declassified result of an equal-length authentication comparison.
#[must_use = "the authentication decision must be checked"]
pub struct Verification {
    choice: Choice,
}

impl Verification {
    pub(crate) const fn new(choice: Choice) -> Self {
        Self { choice }
    }

    /// Reveals only the final authentication decision.
    pub const fn expose_public(self) -> bool {
        self.choice.expose_public()
    }
}
