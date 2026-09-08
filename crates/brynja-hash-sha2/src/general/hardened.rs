use super::{Sha512TBits, Sha512TDigest, Sha512TError, Sha512TSecretDigest, secret};
use crate::{
    BitString, PublicDeclassification,
    hardened::{HardenedSha2Owner, finalize_bits_length64},
};
use brynja_core::SecretRegionInitialization;

/// Sealed hardened general SHA-512/t state, using the reviewed SHA-2 owner.
/// All source-declared secret storage clears on success, error, cancel, unwind
/// and Drop. No register/spill/cache/abort or caller-copy erasure is promised.
/// Fixed storage; no CPU backend, cloning, reset, formatting or state import.
pub struct HardenedSha512T {
    parameter: Sha512TBits,
    owner: HardenedSha2Owner,
}

impl HardenedSha512T {
    /// Maximum valid total message length in bits.
    pub const MAX_MESSAGE_BITS: u128 = u128::MAX;
    /// Maximum complete-byte message length.
    pub const MAX_MESSAGE_BYTES: u128 = u128::MAX / 8;
    /// Derives a public IV before any secret is accepted.
    #[must_use]
    pub fn new(parameter: Sha512TBits) -> Self {
        Self {
            parameter,
            owner: HardenedSha2Owner::new64(parameter.initial_words()),
        }
    }
    /// Public algorithm parameter.
    #[must_use]
    pub const fn parameter(&self) -> Sha512TBits {
        self.parameter
    }
    /// Accepted complete-byte count; lengths are public metadata.
    #[must_use]
    pub fn message_bytes(&self) -> u128 {
        self.owner.message_bytes64()
    }
    /// Checks without mutation.
    pub fn check_additional_bytes(&self, count: u128) -> Result<(), Sha512TError> {
        self.owner
            .check_bytes64(count)
            .map_err(|_| Sha512TError::MessageTooLong)
    }
    /// Checks without mutation.
    pub fn check_additional_bits(&self, count: u128) -> Result<(), Sha512TError> {
        self.owner
            .check_bits64(count)
            .map_err(|_| Sha512TError::MessageTooLong)
    }
    /// Complete bytes are admitted before mutation. Caller inputs are not erased.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Sha512TError> {
        self.owner
            .update64(input)
            .map_err(|_| Sha512TError::MessageTooLong)
    }
    /// Consumes and clears the state without producing output.
    pub fn cancel(self) {
        drop(self);
    }
    /// Consumes the state with deliberate public declassification.
    pub fn finalize_public(
        mut self,
        authority: PublicDeclassification,
    ) -> Result<Sha512TDigest, Sha512TError> {
        self.finish_public(None, authority)
    }
    /// Consumes the state with a final MSB-first tail and public declassification.
    pub fn finalize_bits_public(
        mut self,
        input: BitString<'_>,
        authority: PublicDeclassification,
    ) -> Result<Sha512TDigest, Sha512TError> {
        self.finish_public(Some(input), authority)
    }
    /// Transfers a typed secret owner; every error clears the entire destination.
    /// Invalid destination clearing costs O(destination length).
    pub fn finalize_secret(
        mut self,
        destination: &mut [u8],
    ) -> Result<Sha512TSecretDigest<'_>, Sha512TError> {
        let guard = secret::begin(self.parameter, destination)?;
        self.finish_secret(None, guard)
    }
    /// Consumes a final canonical bit string; error clears the whole destination.
    pub fn finalize_bits_secret<'a>(
        mut self,
        input: BitString<'_>,
        destination: &'a mut [u8],
    ) -> Result<Sha512TSecretDigest<'a>, Sha512TError> {
        let guard = secret::begin(self.parameter, destination)?;
        self.finish_secret(Some(input), guard)
    }
    fn finish_public(
        &mut self,
        input: Option<BitString<'_>>,
        _authority: PublicDeclassification,
    ) -> Result<Sha512TDigest, Sha512TError> {
        self.finish(input)?;
        Sha512TDigest::computed(self.parameter, &self.owner.output_staging)
    }
    pub(super) fn finish_secret<'a>(
        &mut self,
        input: Option<BitString<'_>>,
        mut guard: SecretRegionInitialization<'a>,
    ) -> Result<Sha512TSecretDigest<'a>, Sha512TError> {
        self.finish(input)?;
        guard.write(
            self.owner
                .staged(self.parameter.output_bytes())
                .ok_or(Sha512TError::OutputLength)?,
        )?;
        Ok(Sha512TSecretDigest::from_region(
            self.parameter,
            guard.finish()?,
        ))
    }
    fn finish(&mut self, input: Option<BitString<'_>>) -> Result<(), Sha512TError> {
        let (partial, bits) = if let Some(input) = input {
            let bits = finalize_bits_length64(&self.owner, input)
                .map_err(|_| Sha512TError::MessageTooLong)?;
            let (complete, partial) = input.split();
            self.update(complete)?;
            (partial, bits)
        } else {
            (
                None,
                self.message_bytes()
                    .checked_mul(8)
                    .ok_or(Sha512TError::MessageTooLong)?,
            )
        };
        self.owner
            .finalize64(partial, bits, self.parameter.output_bytes());
        if let Some(last) = self
            .owner
            .output_staging
            .get_mut(self.parameter.output_bytes().saturating_sub(1))
        {
            *last &= self.parameter.last_byte_mask();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
