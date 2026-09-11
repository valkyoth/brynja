use super::{
    Error, Mode, Report,
    backend::State,
    output::{BorrowedStage, length_bits},
};
use crate::{
    Fips202BitString, KmacKeyPolicy, KmacSecretOutput,
    packer::{Absorb, absorb_key, append_suffix},
};
use brynja_core::clear_owned_region;

pub(super) struct Core<'a> {
    state: State<'a>,
    metadata: Metadata,
    strength: u128,
}

pub(super) struct Metadata {
    message_bytes: [u8; 16],
    output_bits: [u8; 16],
    phase: [u8; 1],
    key_class: [u8; 1],
}

impl Metadata {
    #[inline(never)]
    fn wipe(&mut self) {
        let _ = clear_owned_region(&mut self.message_bytes);
        let _ = clear_owned_region(&mut self.output_bits);
        let _ = clear_owned_region(&mut self.phase);
        let _ = clear_owned_region(&mut self.key_class);
    }
}
impl Drop for Metadata {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl<'a> Core<'a> {
    pub(super) fn new(
        mode: Mode<'a>,
        wide: bool,
        key: Fips202BitString<'_>,
        customization: Fips202BitString<'_>,
        conformance: bool,
    ) -> Result<Self, Error> {
        let strength = if wide { 256 } else { 128 };
        let key_bits = u128::try_from(key.bit_len()).map_err(|_| Error::MessageTooLong)?;
        if !conformance && key_bits < strength {
            return Err(Error::KeyTooShort);
        }
        let mut core = Self {
            state: State::new(mode, wide, customization)?,
            metadata: Metadata {
                message_bytes: [0; 16],
                output_bits: [0; 16],
                phase: [1],
                key_class: [u8::from(key_bits >= strength)],
            },
            strength,
        };
        absorb_key(&mut core.state, key, if wide { 136 } else { 168 })?;
        Ok(core)
    }

    pub(super) fn report(&self) -> Option<Report> {
        self.state.report()
    }
    pub(super) fn key_policy(&self) -> KmacKeyPolicy {
        if self.metadata.key_class == [1] {
            KmacKeyPolicy::FullStrength
        } else {
            KmacKeyPolicy::ConformanceOnly
        }
    }
    pub(super) fn message_bytes(&self) -> u128 {
        u128::from_le_bytes(self.metadata.message_bytes)
    }
    pub(super) fn output_bits(&self) -> u128 {
        u128::from_le_bytes(self.metadata.output_bits)
    }
    pub(super) fn strength(&self) -> u128 {
        self.strength
    }

    fn phase(&self, expected: u8) -> Result<(), Error> {
        if self.metadata.phase == [expected] {
            Ok(())
        } else {
            Err(Error::StateConsumed)
        }
    }

    pub(super) fn update(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let mut operation = Operation::new(self);
        operation.core.phase(1)?;
        let length = u128::try_from(bytes.len()).map_err(|_| Error::MessageTooLong)?;
        let updated = operation
            .core
            .message_bytes()
            .checked_add(length)
            .ok_or(Error::MessageTooLong)?;
        operation.core.state.absorb(bytes)?;
        operation
            .core
            .metadata
            .message_bytes
            .copy_from_slice(&updated.to_le_bytes());
        operation.completed = true;
        Ok(())
    }

    pub(super) fn finish(
        &mut self,
        message: Option<Fips202BitString<'_>>,
        bits: u128,
        xof: bool,
        conformance: bool,
    ) -> Result<(), Error> {
        let mut operation = Operation::new(self);
        operation.core.phase(1)?;
        if !conformance && operation.core.key_policy() != KmacKeyPolicy::FullStrength {
            return Err(Error::KeyTooShort);
        }
        if !xof && !conformance && bits < operation.core.strength {
            return Err(Error::TagTooShort);
        }
        let tail = append_suffix(
            &mut operation.core.state,
            message,
            if xof { 0 } else { bits },
        )?;
        let input = match tail.as_ref() {
            Some(tail) => Fips202BitString::new(tail.as_bytes(), tail.valid())
                .map_err(|_| Error::InvalidBitString)?,
            None => super::bits(&[])?,
        };
        operation.core.state.finish(input)?;
        operation.core.metadata.phase = [2];
        operation.completed = true;
        Ok(())
    }

    pub(super) fn public(
        &mut self,
        output: &mut [u8],
        valid: u8,
        scratch: &mut [u8],
        terminal: bool,
    ) -> Result<(), Error> {
        let stage = BorrowedStage(scratch);
        let mut operation = Operation::new(self);
        operation.core.phase(2)?;
        let bits = length_bits(output.len(), valid)?;
        let updated = operation
            .core
            .output_bits()
            .checked_add(bits)
            .ok_or(Error::OutputTooLong)?;
        let buffer = stage
            .0
            .get_mut(..output.len())
            .ok_or(Error::OutputTooLong)?;
        operation.core.state.public(output, buffer)?;
        if valid != 0
            && valid != 8
            && let Some(last) = output.last_mut()
        {
            *last &= u8::MAX >> 8_u8.checked_sub(valid).ok_or(Error::InvalidBitString)?;
        }
        operation
            .core
            .metadata
            .output_bits
            .copy_from_slice(&updated.to_le_bytes());
        operation.completed = true;
        if terminal {
            operation.core.cancel();
        }
        Ok(())
    }

    pub(super) fn secret<'out>(
        &mut self,
        output: &'out mut [u8],
        valid: u8,
        terminal: bool,
    ) -> Result<KmacSecretOutput<'out>, Error> {
        let mut operation = Operation::new(self);
        let _ = clear_owned_region(output);
        operation.core.phase(2)?;
        let bits = length_bits(output.len(), valid)?;
        let updated = operation
            .core
            .output_bits()
            .checked_add(bits)
            .ok_or(Error::OutputTooLong)?;
        let result = operation.core.state.secret(output, valid, terminal)?;
        operation
            .core
            .metadata
            .output_bits
            .copy_from_slice(&updated.to_le_bytes());
        operation.completed = true;
        if terminal {
            operation.core.cancel();
        }
        Ok(KmacSecretOutput::new(result))
    }

    #[inline(never)]
    pub(super) fn cancel(&mut self) {
        self.state.wipe();
        self.metadata.wipe();
    }
}

impl Drop for Core<'_> {
    fn drop(&mut self) {
        self.cancel();
    }
}

pub(super) struct Operation<'s, 'a> {
    core: &'s mut Core<'a>,
    completed: bool,
}
impl<'s, 'a> Operation<'s, 'a> {
    fn new(core: &'s mut Core<'a>) -> Self {
        Self {
            core,
            completed: false,
        }
    }
}
impl Drop for Operation<'_, '_> {
    fn drop(&mut self) {
        if !self.completed {
            self.core.cancel();
        }
    }
}

#[cfg(test)]
mod tests;
