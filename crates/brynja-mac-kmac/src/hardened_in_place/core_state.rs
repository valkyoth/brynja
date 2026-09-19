use super::backend::{Borrowed, Reader, State};
use crate::{
    Fips202BitString, Fips202Output, KmacError, KmacKeyPolicy, KmacSecretOutput, KmacTag,
    KmacVerification,
    packer::{Absorb, absorb_key, append_suffix},
    policy::tag_policy,
};
use brynja_core::clear_owned_region;

#[cfg(test)]
mod tests;

pub(super) struct Metadata {
    key_class: [u8; 1],
    verification: [u8; 64],
    difference: [u8; 1],
}
impl Metadata {
    pub(super) const fn new() -> Self {
        Self {
            key_class: [0],
            verification: [0; 64],
            difference: [0],
        }
    }
    pub(super) fn wipe(&mut self) {
        let _ = clear_owned_region(&mut self.key_class);
        let _ = clear_owned_region(&mut self.verification);
        let _ = clear_owned_region(&mut self.difference);
    }
    #[cfg(test)]
    pub(super) fn poison(&mut self) {
        self.key_class.fill(0xa5);
        self.verification.fill(0xa5);
        self.difference.fill(0xa5);
    }
    #[cfg(test)]
    pub(super) fn cleared(&self) -> bool {
        self.key_class == [0] && self.difference == [0] && self.verification.iter().all(|b| *b == 0)
    }
}
impl Drop for Metadata {
    fn drop(&mut self) {
        self.wipe();
    }
}
pub(super) struct Guard<'scope>(pub(super) &'scope mut Metadata);
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        self.0.wipe();
    }
}

pub(super) struct Core<'scope, S: State> {
    state: Borrowed<S>,
    cleanup: Guard<'scope>,
}
struct Operation<'borrow, 'scope, S: State> {
    core: &'borrow mut Core<'scope, S>,
    complete: bool,
}
impl<S: State> Drop for Operation<'_, '_, S> {
    fn drop(&mut self) {
        if !self.complete {
            self.core.state.0 = None;
            self.core.cleanup.0.wipe();
        }
    }
}
impl<'scope, S: State> Core<'scope, S> {
    pub(super) fn new(
        state: S,
        metadata: &'scope mut Metadata,
        key: Fips202BitString<'_>,
        rate: usize,
        strength: u128,
    ) -> Result<Self, KmacError> {
        let mut core = Self {
            state: Borrowed(Some(state)),
            cleanup: Guard(metadata),
        };
        let key_bits = u128::try_from(key.bit_len()).map_err(|_| KmacError::MessageTooLong)?;
        core.cleanup.0.key_class = [u8::from(key_bits >= strength)];
        absorb_key(&mut core.state, key, rate)?;
        Ok(core)
    }
    pub(super) fn key_policy(&self) -> KmacKeyPolicy {
        if self.cleanup.0.key_class == [1] {
            KmacKeyPolicy::FullStrength
        } else {
            KmacKeyPolicy::ConformanceOnly
        }
    }
    pub(super) fn update(&mut self, bytes: &[u8]) -> Result<(), KmacError> {
        let mut operation = Operation {
            core: self,
            complete: false,
        };
        operation.core.state.absorb(bytes)?;
        operation.complete = true;
        Ok(())
    }
    fn finish(
        mut self,
        input: Option<Fips202BitString<'_>>,
        bits: u128,
        strength: u128,
        production: bool,
    ) -> Result<(S::Reader, Guard<'scope>), KmacError> {
        if self.state.0.is_none() {
            return Err(KmacError::StateConsumed);
        }
        if production && self.key_policy() != KmacKeyPolicy::FullStrength {
            return Err(KmacError::KeyTooShort);
        }
        if production && bits < strength {
            return Err(KmacError::TagTooShort);
        }
        let reader = append_suffix(&mut self.state, input, bits, |state, tail| {
            state.0.take().ok_or(KmacError::StateConsumed)?.finish(tail)
        })?;
        Ok((reader, self.cleanup))
    }
    pub(super) fn finish_xof(
        self,
        input: Option<Fips202BitString<'_>>,
        production: bool,
    ) -> Result<(S::Reader, Guard<'scope>), KmacError> {
        if self.state.0.is_none() {
            return Err(KmacError::StateConsumed);
        }
        if production && self.key_policy() != KmacKeyPolicy::FullStrength {
            return Err(KmacError::KeyTooShort);
        }
        // KMACXOF frames right_encode(0), not the requested output length.
        // Key strength was checked above; fixed-tag minimums do not apply.
        self.finish(input, 0, 0, false)
    }
    pub(super) fn tag<'out>(
        self,
        input: Option<Fips202BitString<'_>>,
        output: &'out mut [u8],
        valid: u8,
        strength: u128,
        production: bool,
    ) -> Result<KmacTag<'out>, KmacError> {
        let bits = output_bits(output.len(), valid)?;
        let (reader, _cleanup) = self.finish(input, bits, strength, production)?;
        reader.final_public(
            Fips202Output::new(output, valid).map_err(|_| KmacError::InvalidBitString)?,
        )?;
        Ok(KmacTag::new(output, bits, tag_policy(bits, strength)))
    }
    pub(super) fn secret<'out>(
        self,
        input: Option<Fips202BitString<'_>>,
        output: &'out mut [u8],
        valid: u8,
        strength: u128,
        production: bool,
    ) -> Result<KmacSecretOutput<'out>, KmacError> {
        // Establish whole-destination clearing before shape/strength/finalization.
        let _ = clear_owned_region(output);
        let bits = output_bits(output.len(), valid)?;
        let (reader, _cleanup) = self.finish(input, bits, strength, production)?;
        reader
            .final_secret(output, valid)
            .map(KmacSecretOutput::new)
    }
    pub(super) fn verify(
        self,
        input: Option<Fips202BitString<'_>>,
        candidate: Fips202BitString<'_>,
        expected: Option<u128>,
        strength: u128,
        production: bool,
    ) -> Result<KmacVerification, KmacError> {
        let bits = u128::try_from(candidate.bit_len()).map_err(|_| KmacError::OutputTooLong)?;
        if expected.is_some_and(|expected| bits != expected) {
            return Err(KmacError::InvalidBitString);
        }
        let (mut reader, cleanup) = self.finish(input, bits, strength, production)?;
        let length = candidate.as_bytes().len();
        let split = if candidate.is_byte_aligned() {
            length
        } else {
            length.checked_sub(1).ok_or(KmacError::InvalidBitString)?
        };
        let complete = candidate
            .as_bytes()
            .get(..split)
            .ok_or(KmacError::InvalidBitString)?;
        for expected in complete.chunks(64) {
            let output = cleanup
                .0
                .verification
                .get_mut(..expected.len())
                .ok_or(KmacError::OutputTooLong)?;
            let secret = reader.secret(output)?;
            for (actual, expected) in secret.expose().iter().zip(expected) {
                for difference in &mut cleanup.0.difference {
                    brynja_core::accumulate_secret_byte_difference(difference, actual, expected);
                }
            }
        }
        if !candidate.is_byte_aligned() {
            let expected = candidate
                .as_bytes()
                .last()
                .ok_or(KmacError::InvalidBitString)?;
            let valid = candidate.valid_bits_in_last_byte();
            let output = cleanup
                .0
                .verification
                .get_mut(..1)
                .ok_or(KmacError::OutputTooLong)?;
            let secret = reader.final_secret(output, valid)?;
            let actual = secret.expose().first().ok_or(KmacError::SecretMemory)?;
            for difference in &mut cleanup.0.difference {
                brynja_core::accumulate_secret_byte_difference(difference, actual, expected);
            }
        }
        Ok(KmacVerification::new(
            brynja_core::secret_difference_is_zero(&cleanup.0.difference[0]),
        ))
    }
}

pub(super) fn bytes(input: &[u8]) -> Result<Fips202BitString<'_>, KmacError> {
    Fips202BitString::new(input, byte_valid(input.len())).map_err(|_| KmacError::InvalidBitString)
}
pub(super) const fn byte_valid(length: usize) -> u8 {
    if length == 0 { 0 } else { 8 }
}
fn output_bits(length: usize, valid: u8) -> Result<u128, KmacError> {
    if length == 0 {
        return if valid == 0 {
            Ok(0)
        } else {
            Err(KmacError::InvalidBitString)
        };
    }
    if !(1..=8).contains(&valid) {
        return Err(KmacError::InvalidBitString);
    }
    u128::try_from(length.checked_sub(1).ok_or(KmacError::OutputTooLong)?)
        .ok()
        .and_then(|n| n.checked_mul(8))
        .and_then(|n| n.checked_add(u128::from(valid)))
        .ok_or(KmacError::OutputTooLong)
}
