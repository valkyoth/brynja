use super::{
    Error, Mode, Report,
    backend::State,
    output::{BorrowedStage, length_bits},
};
use crate::{Fips202BitString, TupleHashSecretOutput, secret_encoding::SecretEncodedInteger};
use brynja_core::clear_owned_region;

pub(super) struct Core<'a> {
    state: State<'a>,
    metadata: Metadata,
}

struct Metadata {
    pending: [u8; 1],
    used: [u8; 1],
    items: [u8; 16],
    remaining: [u8; 16],
    input_bits: [u8; 16],
    output_bits: [u8; 16],
    phase: [u8; 1],
    staging: [u8; 168],
}
impl Metadata {
    #[inline(never)]
    fn wipe(&mut self) {
        let _ = clear_owned_region(&mut self.pending);
        let _ = clear_owned_region(&mut self.used);
        let _ = clear_owned_region(&mut self.items);
        let _ = clear_owned_region(&mut self.remaining);
        let _ = clear_owned_region(&mut self.input_bits);
        let _ = clear_owned_region(&mut self.output_bits);
        let _ = clear_owned_region(&mut self.phase);
        let _ = clear_owned_region(&mut self.staging);
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
        custom: Fips202BitString<'_>,
    ) -> Result<Self, Error> {
        Ok(Self {
            state: State::new(mode, wide, custom)?,
            metadata: Metadata {
                pending: [0],
                used: [0],
                items: [0; 16],
                remaining: [0; 16],
                input_bits: [0; 16],
                output_bits: [0; 16],
                phase: [1],
                staging: [0; 168],
            },
        })
    }
    pub(super) fn report(&self) -> Option<Report> {
        self.state.report()
    }
    pub(super) fn item_count(&self) -> u128 {
        read_counter(&self.metadata.items)
    }
    pub(super) fn remaining_bits(&self) -> u128 {
        read_counter(&self.metadata.remaining)
    }
    pub(super) fn output_bits(&self) -> u128 {
        read_counter(&self.metadata.output_bits)
    }
    fn input_bits(&self) -> u128 {
        read_counter(&self.metadata.input_bits)
    }

    fn phase(&self, expected: u8) -> Result<(), Error> {
        if self.metadata.phase == [expected] {
            Ok(())
        } else if self.metadata.phase == [2] {
            Err(Error::IncompleteItem)
        } else {
            Err(Error::StateConsumed)
        }
    }

    pub(super) fn begin(&mut self, bits: u128) -> Result<(), Error> {
        let mut operation = Operation::new(self);
        let core = &mut operation.core;
        core.phase(1)?;
        core.state.update(&[])?;
        let prefix = SecretEncodedInteger::left(bits)?;
        let bytes = prefix.as_bytes()?;
        let prefix_bits = super::output::byte_bits(bytes.len())?;
        // Pre-flight the eventual total (prefix + complete declared item) before
        // absorption. Only the prefix is committed below; fragment() accounts
        // for body bits as they arrive. This is not a redundant prefix check.
        core.input_bits()
            .checked_add(prefix_bits)
            .and_then(|n| n.checked_add(bits))
            .ok_or(Error::MessageTooLong)?;
        // Reserve capacity for eventual completion without counting an item
        // until its exact declared body has been supplied to complete().
        core.item_count()
            .checked_add(1)
            .ok_or(Error::MessageTooLong)?;
        core.append(bytes)?;
        let total = core
            .input_bits()
            .checked_add(prefix_bits)
            .ok_or(Error::MessageTooLong)?;
        write_counter(&mut core.metadata.input_bits, total)?;
        write_counter(&mut core.metadata.remaining, bits)?;
        core.metadata.phase = [2];
        operation.completed = true;
        Ok(())
    }

    pub(super) fn fragment(&mut self, input: Fips202BitString<'_>) -> Result<(), Error> {
        let mut operation = Operation::new(self);
        let core = &mut operation.core;
        core.phase(2)?;
        core.state.update(&[])?;
        let count = u128::try_from(input.bit_len()).map_err(|_| Error::MessageTooLong)?;
        let remaining = crate::core_state::checked_remaining_after(core.remaining_bits(), count)?;
        let total = core
            .input_bits()
            .checked_add(count)
            .ok_or(Error::MessageTooLong)?;
        let bytes = input.as_bytes();
        if input.is_byte_aligned() {
            core.append(bytes)?;
        } else {
            let (last, prefix) = bytes.split_last().ok_or(Error::InvalidBitString)?;
            core.append(prefix)?;
            core.append_bits(*last, input.valid_bits_in_last_byte())?;
        }
        write_counter(&mut core.metadata.remaining, remaining)?;
        write_counter(&mut core.metadata.input_bits, total)?;
        operation.completed = true;
        Ok(())
    }

    pub(super) fn complete(&mut self) -> Result<(), Error> {
        let mut operation = Operation::new(self);
        let core = &mut operation.core;
        core.phase(2)?;
        core.state.update(&[])?;
        if core.remaining_bits() != 0 {
            return Err(Error::IncompleteItem);
        }
        let count = core
            .item_count()
            .checked_add(1)
            .ok_or(Error::MessageTooLong)?;
        write_counter(&mut core.metadata.items, count)?;
        let _ = clear_owned_region(&mut core.metadata.remaining);
        core.metadata.phase = [1];
        operation.completed = true;
        Ok(())
    }

    // Whole byte fragments stay bulk-absorbed even after a partial tuple item.
    // The only copy is bounded owned staging, erased before return and on unwind.
    fn append(&mut self, input: &[u8]) -> Result<(), Error> {
        let used = self.metadata.used[0];
        if used == 0 {
            return self.state.update(input);
        }
        if used >= 8 {
            return Err(Error::SecretMemory);
        }
        let carry_shift = 8_u8.checked_sub(used).ok_or(Error::SecretMemory)?;
        for chunk in input.chunks(168) {
            for (byte, target) in chunk.iter().zip(self.metadata.staging.iter_mut()) {
                *target = self.metadata.pending[0] | (*byte << used);
                self.metadata.pending[0] = *byte >> carry_shift;
            }
            self.state.update(
                self.metadata
                    .staging
                    .get(..chunk.len())
                    .ok_or(Error::SecretMemory)?,
            )?;
            let _ = clear_owned_region(&mut self.metadata.staging);
        }
        Ok(())
    }
    fn append_bits(&mut self, byte: u8, valid: u8) -> Result<(), Error> {
        if valid > 8 || self.metadata.used[0] >= 8 {
            return Err(Error::InvalidBitString);
        }
        for position in 0..valid {
            self.metadata.pending[0] |= ((byte >> position) & 1) << self.metadata.used[0];
            self.metadata.used[0] = self.metadata.used[0]
                .checked_add(1)
                .ok_or(Error::MessageTooLong)?;
            if self.metadata.used == [8] {
                self.state.update(&self.metadata.pending)?;
                let _ = clear_owned_region(&mut self.metadata.pending);
                let _ = clear_owned_region(&mut self.metadata.used);
            }
        }
        Ok(())
    }

    pub(super) fn finish(&mut self, bits: u128) -> Result<(), Error> {
        let mut operation = Operation::new(self);
        let core = &mut operation.core;
        core.phase(1)?;
        core.state.update(&[])?;
        let suffix = SecretEncodedInteger::right(bits)?;
        let bytes = suffix.as_bytes()?;
        core.input_bits()
            .checked_add(super::output::byte_bits(bytes.len())?)
            .ok_or(Error::MessageTooLong)?;
        core.append(bytes)?;
        let tail = if core.metadata.used == [0] {
            super::bits(&[])?
        } else {
            Fips202BitString::new(&core.metadata.pending, core.metadata.used[0])
                .map_err(|_| Error::InvalidBitString)?
        };
        core.state.finish(tail)?;
        core.metadata.wipe();
        core.metadata.phase = [3];
        operation.completed = true;
        Ok(())
    }

    pub(super) fn public(
        &mut self,
        bytes: &mut [u8],
        valid: u8,
        scratch: &mut [u8],
        terminal: bool,
    ) -> Result<(), Error> {
        let stage = BorrowedStage(scratch);
        let mut operation = Operation::new(self);
        let core = &mut operation.core;
        core.phase(3)?;
        let bits = length_bits(bytes.len(), valid)?;
        let mask = if valid == 0 {
            u8::MAX
        } else {
            u8::MAX >> 8_u8.checked_sub(valid).ok_or(Error::InvalidBitString)?
        };
        let total = core
            .output_bits()
            .checked_add(bits)
            .ok_or(Error::OutputTooLong)?;
        let buffer = stage.0.get_mut(..bytes.len()).ok_or(Error::OutputTooLong)?;
        core.state.public(bytes, buffer)?;
        if valid != 0
            && valid != 8
            && let Some(last) = bytes.last_mut()
        {
            *last &= mask;
        }
        write_counter(&mut core.metadata.output_bits, total)?;
        if terminal {
            core.cancel();
        }
        operation.completed = true;
        Ok(())
    }

    pub(super) fn secret<'out>(
        &mut self,
        bytes: &'out mut [u8],
        valid: u8,
        terminal: bool,
    ) -> Result<TupleHashSecretOutput<'out>, Error> {
        let _ = clear_owned_region(bytes);
        let mut operation = Operation::new(self);
        let core = &mut operation.core;
        core.phase(3)?;
        let bits = length_bits(bytes.len(), valid)?;
        let total = core
            .output_bits()
            .checked_add(bits)
            .ok_or(Error::OutputTooLong)?;
        let output = core.state.secret(bytes, valid, terminal)?;
        write_counter(&mut core.metadata.output_bits, total)?;
        if terminal {
            core.cancel();
        }
        operation.completed = true;
        Ok(TupleHashSecretOutput::new(output))
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

struct Operation<'s, 'a> {
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

// Encode counters directly into their owned byte regions, without temporary
// stack arrays. Scalar register/compiler-copy residuals still apply.
fn read_counter(bytes: &[u8; 16]) -> u128 {
    let mut value = 0_u128;
    for (index, byte) in bytes.iter().enumerate() {
        value |= u128::from(*byte) << index.saturating_mul(8);
    }
    value
}
fn write_counter(bytes: &mut [u8; 16], value: u128) -> Result<(), Error> {
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::try_from((value >> index.saturating_mul(8)) & u128::from(u8::MAX))
            .map_err(|_| Error::SecretMemory)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
