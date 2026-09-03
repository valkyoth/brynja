use brynja_core::{Choice, ConstantTimeEq, clear_owned_region};
use brynja_hash_sha3::HardenedSha3SecretOutput;

use crate::policy::{KmacServiceStatus, KmacTagPolicy};

/// Explicit authority to release KMACXOF output as public bytes.
#[must_use = "public declassification must be consumed by an output operation"]
pub struct KmacPublicDeclassification {
    _private: (),
}

impl KmacPublicDeclassification {
    /// Acknowledges that the selected KMACXOF bytes are public output.
    pub const fn acknowledge() -> Self {
        Self { _private: () }
    }
}

/// Borrowed, opaque public fixed KMAC tag.
///
/// This type intentionally implements no ordinary equality or formatting.
#[must_use = "the generated authenticator must be consumed"]
pub struct KmacTag<'tag> {
    bytes: &'tag [u8],
    bit_length: u128,
    policy: KmacTagPolicy,
}

impl<'tag> KmacTag<'tag> {
    pub(crate) const fn new(bytes: &'tag [u8], bit_length: u128, policy: KmacTagPolicy) -> Self {
        Self {
            bytes,
            bit_length,
            policy,
        }
    }

    /// Borrows the public authenticator bytes for transport.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        self.bytes
    }

    /// Returns the exact number of significant bits in the tag.
    #[must_use]
    pub const fn bit_len(&self) -> u128 {
        self.bit_length
    }

    /// Returns the output-length policy classification.
    #[must_use]
    pub const fn policy(&self) -> KmacTagPolicy {
        self.policy
    }

    /// Reports the current non-approved service status.
    #[must_use]
    pub const fn service_status(&self) -> KmacServiceStatus {
        KmacServiceStatus::NonApproved
    }

    /// Compares another same-purpose byte tag without content-dependent exit.
    pub fn verify_candidate(&self, candidate: &[u8]) -> KmacVerification {
        compare_bytes(self.bytes, candidate)
    }
}

/// Typed ownership of one secret KMAC or KMACXOF output.
#[must_use = "secret output must remain owned or be dropped for clearing"]
pub struct KmacSecretOutput<'output> {
    inner: HardenedSha3SecretOutput<'output>,
}

impl<'output> KmacSecretOutput<'output> {
    pub(crate) const fn new(inner: HardenedSha3SecretOutput<'output>) -> Self {
        Self { inner }
    }

    /// Borrows the completely initialized secret output.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.inner.expose()
    }
}

/// Opaque result of one constant-time KMAC verification.
#[must_use = "the verification decision must be explicitly declassified"]
pub struct KmacVerification {
    choice: Choice,
}

impl KmacVerification {
    pub(crate) const fn new(choice: Choice) -> Self {
        Self { choice }
    }

    /// Declassifies the final authentication decision.
    #[must_use]
    pub const fn expose_public(self) -> bool {
        self.choice.expose_public()
    }
}

pub(crate) fn compare_bytes(expected: &[u8], candidate: &[u8]) -> KmacVerification {
    let mut difference = VerificationDifference::new();
    for (left, right) in expected.iter().zip(candidate.iter()) {
        difference.accumulate(*left ^ *right);
    }
    let lengths = expected.len().ct_eq(&candidate.len());
    KmacVerification::new(lengths.and(difference.is_zero()))
}

pub(crate) struct VerificationDifference {
    value: [u8; 1],
}

impl VerificationDifference {
    pub(crate) const fn new() -> Self {
        Self { value: [0] }
    }

    pub(crate) fn accumulate(&mut self, value: u8) {
        if let Some(current) = self.value.first_mut() {
            *current |= value;
        }
    }

    pub(crate) fn is_zero(&self) -> Choice {
        self.value.ct_eq(&[0])
    }
}

impl Drop for VerificationDifference {
    fn drop(&mut self) {
        let _ = clear_owned_region(&mut self.value);
    }
}
