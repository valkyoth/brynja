use super::backend::{Reader, State};
use crate::{
    Fips202BitString, Fips202Output, TupleHashError, TupleHashSecretOutput,
    secret_encoding::SecretEncodedInteger,
};
use brynja_core::clear_owned_region;

pub(super) struct Metadata {
    pending: [u8; 1],
    used: [u8; 1],
    items: [u8; 16],
    remaining: [u8; 16],
    input_bits: [u8; 16],
    phase: [u8; 1],
    staging: [u8; 168],
}
impl Metadata {
    pub(super) const fn new() -> Self {
        Self {
            pending: [0],
            used: [0],
            items: [0; 16],
            remaining: [0; 16],
            input_bits: [0; 16],
            phase: [0],
            staging: [0; 168],
        }
    }
    pub(super) fn wipe(&mut self) {
        let _ = clear_owned_region(&mut self.pending);
        let _ = clear_owned_region(&mut self.used);
        let _ = clear_owned_region(&mut self.items);
        let _ = clear_owned_region(&mut self.remaining);
        let _ = clear_owned_region(&mut self.input_bits);
        let _ = clear_owned_region(&mut self.phase);
        let _ = clear_owned_region(&mut self.staging);
    }
    #[cfg(test)]
    pub(super) fn poison(&mut self) {
        self.pending.fill(0xa5);
        self.used.fill(0xa5);
        self.items.fill(0xa5);
        self.remaining.fill(0xa5);
        self.input_bits.fill(0xa5);
        self.phase.fill(0xa5);
        self.staging.fill(0xa5);
    }
    #[cfg(test)]
    pub(super) fn cleared(&self) -> bool {
        self.pending == [0]
            && self.used == [0]
            && self.items == [0; 16]
            && self.remaining == [0; 16]
            && self.input_bits == [0; 16]
            && self.phase == [0]
            && self.staging == [0; 168]
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
    state: Option<S>,
    cleanup: Guard<'scope>,
}
struct Operation<'borrow, 'scope, S: State> {
    core: &'borrow mut Core<'scope, S>,
    complete: bool,
}
impl<S: State> Drop for Operation<'_, '_, S> {
    fn drop(&mut self) {
        if !self.complete {
            self.core.cancel();
        }
    }
}
impl<'scope, S: State> Core<'scope, S> {
    pub(super) fn new(state: S, metadata: &'scope mut Metadata) -> Self {
        metadata.wipe();
        metadata.phase = [1];
        Self {
            state: Some(state),
            cleanup: Guard(metadata),
        }
    }
    pub(super) fn cancel(&mut self) {
        self.state = None;
        self.cleanup.0.wipe();
    }
    #[cfg(test)]
    pub(super) fn terminal_and_cleared(&self) -> bool {
        self.state.is_none() && self.cleanup.0.cleared()
    }
    fn phase(&self, expected: u8) -> Result<(), TupleHashError> {
        if self.state.is_none() || self.cleanup.0.phase == [0] {
            Err(TupleHashError::StateConsumed)
        } else if self.cleanup.0.phase == [expected] {
            Ok(())
        } else {
            Err(TupleHashError::IncompleteItem)
        }
    }
    pub(super) fn begin(&mut self, bits: u128) -> Result<(), TupleHashError> {
        let mut operation = Operation {
            core: self,
            complete: false,
        };
        let core = &mut operation.core;
        core.phase(1)?;
        let mut prefix = SecretEncodedInteger::empty();
        prefix.left(bits)?;
        let bytes = prefix.as_bytes()?;
        let prefix_bits = crate::core_state::output_bits(bytes.len())?;
        let total = read(&core.cleanup.0.input_bits)
            .checked_add(prefix_bits)
            .ok_or(TupleHashError::MessageTooLong)?;
        total
            .checked_add(bits)
            .ok_or(TupleHashError::MessageTooLong)?;
        read(&core.cleanup.0.items)
            .checked_add(1)
            .ok_or(TupleHashError::MessageTooLong)?;
        core.append(bytes)?;
        write(&mut core.cleanup.0.input_bits, total)?;
        write(&mut core.cleanup.0.remaining, bits)?;
        core.cleanup.0.phase = [2];
        operation.complete = true;
        Ok(())
    }
    pub(super) fn fragment(&mut self, input: Fips202BitString<'_>) -> Result<(), TupleHashError> {
        let mut operation = Operation {
            core: self,
            complete: false,
        };
        let core = &mut operation.core;
        core.phase(2)?;
        let count = u128::try_from(input.bit_len()).map_err(|_| TupleHashError::MessageTooLong)?;
        let remaining =
            crate::core_state::checked_remaining_after(read(&core.cleanup.0.remaining), count)?;
        let total = read(&core.cleanup.0.input_bits)
            .checked_add(count)
            .ok_or(TupleHashError::MessageTooLong)?;
        if input.is_byte_aligned() {
            core.append(input.as_bytes())?;
        } else {
            let (last, prefix) = input
                .as_bytes()
                .split_last()
                .ok_or(TupleHashError::InvalidBitString)?;
            core.append(prefix)?;
            core.append_bits(*last, input.valid_bits_in_last_byte())?;
        }
        write(&mut core.cleanup.0.remaining, remaining)?;
        write(&mut core.cleanup.0.input_bits, total)?;
        operation.complete = true;
        Ok(())
    }
    pub(super) fn complete(&mut self) -> Result<(), TupleHashError> {
        let mut operation = Operation {
            core: self,
            complete: false,
        };
        let core = &mut operation.core;
        core.phase(2)?;
        if read(&core.cleanup.0.remaining) != 0 {
            return Err(TupleHashError::IncompleteItem);
        }
        let count = read(&core.cleanup.0.items)
            .checked_add(1)
            .ok_or(TupleHashError::MessageTooLong)?;
        write(&mut core.cleanup.0.items, count)?;
        let _ = clear_owned_region(&mut core.cleanup.0.remaining);
        core.cleanup.0.phase = [1];
        operation.complete = true;
        Ok(())
    }
    pub(super) fn item(&mut self, input: Fips202BitString<'_>) -> Result<(), TupleHashError> {
        let bits = u128::try_from(input.bit_len()).map_err(|_| TupleHashError::MessageTooLong)?;
        self.begin(bits)?;
        self.fragment(input)?;
        self.complete()
    }
    pub(super) fn item_bytes(&mut self, input: &[u8]) -> Result<(), TupleHashError> {
        match bytes_input(input) {
            Ok(bits) => self.item(bits),
            Err(error) => {
                self.cancel();
                Err(error)
            }
        }
    }
    pub(super) fn fragment_bytes(&mut self, input: &[u8]) -> Result<(), TupleHashError> {
        match bytes_input(input) {
            Ok(bits) => self.fragment(bits),
            Err(error) => {
                self.cancel();
                Err(error)
            }
        }
    }
    fn append(&mut self, input: &[u8]) -> Result<(), TupleHashError> {
        let state = self.state.as_mut().ok_or(TupleHashError::StateConsumed)?;
        let metadata = &mut *self.cleanup.0;
        let used = metadata.used[0];
        if used == 0 {
            return state.update(input);
        }
        if used >= 8 {
            return Err(TupleHashError::SecretMemory);
        }
        let shift = 8_u8.checked_sub(used).ok_or(TupleHashError::SecretMemory)?;
        // Preserve bulk absorption even after a partial-bit tuple member.
        for chunk in input.chunks(168) {
            for (byte, target) in chunk.iter().zip(metadata.staging.iter_mut()) {
                *target = metadata.pending[0] | (*byte << used);
                metadata.pending[0] = *byte >> shift;
            }
            state.update(
                metadata
                    .staging
                    .get(..chunk.len())
                    .ok_or(TupleHashError::SecretMemory)?,
            )?;
            let _ = clear_owned_region(&mut metadata.staging);
        }
        Ok(())
    }
    fn append_bits(&mut self, byte: u8, valid: u8) -> Result<(), TupleHashError> {
        let state = self.state.as_mut().ok_or(TupleHashError::StateConsumed)?;
        let metadata = &mut *self.cleanup.0;
        if valid > 8 || metadata.used[0] >= 8 {
            return Err(TupleHashError::InvalidBitString);
        }
        for position in 0..valid {
            metadata.pending[0] |= ((byte >> position) & 1) << metadata.used[0];
            metadata.used[0] = metadata.used[0]
                .checked_add(1)
                .ok_or(TupleHashError::MessageTooLong)?;
            if metadata.used == [8] {
                state.update(&metadata.pending)?;
                let _ = clear_owned_region(&mut metadata.pending);
                let _ = clear_owned_region(&mut metadata.used);
            }
        }
        Ok(())
    }
    pub(super) fn finish_xof(self) -> Result<(S::Reader, Guard<'scope>), TupleHashError> {
        self.finish(0)
    }
    fn finish(mut self, bits: u128) -> Result<(S::Reader, Guard<'scope>), TupleHashError> {
        self.phase(1)?;
        let mut suffix = SecretEncodedInteger::empty();
        suffix.right(bits)?;
        let bytes = suffix.as_bytes()?;
        read(&self.cleanup.0.input_bits)
            .checked_add(crate::core_state::output_bits(bytes.len())?)
            .ok_or(TupleHashError::MessageTooLong)?;
        self.append(bytes)?;
        let valid = self.cleanup.0.used[0];
        let tail = if valid == 0 {
            bytes_input(&[])?
        } else {
            Fips202BitString::new(&self.cleanup.0.pending, valid)
                .map_err(|_| TupleHashError::InvalidBitString)?
        };
        let reader = self
            .state
            .take()
            .ok_or(TupleHashError::StateConsumed)?
            .finish(tail)?;
        self.cleanup.0.wipe();
        Ok((reader, self.cleanup))
    }
    pub(super) fn public(self, bytes: &mut [u8], valid: u8) -> Result<(), TupleHashError> {
        let output =
            Fips202Output::new(bytes, valid).map_err(|_| TupleHashError::InvalidBitString)?;
        let bits = u128::try_from(output.bit_len()).map_err(|_| TupleHashError::OutputTooLong)?;
        let (reader, _cleanup) = self.finish(bits)?;
        reader.public(output)
    }
    pub(super) fn secret<'out>(
        self,
        bytes: &'out mut [u8],
        valid: u8,
    ) -> Result<TupleHashSecretOutput<'out>, TupleHashError> {
        let _ = clear_owned_region(bytes);
        let output =
            Fips202Output::new(bytes, valid).map_err(|_| TupleHashError::InvalidBitString)?;
        let bits = u128::try_from(output.bit_len()).map_err(|_| TupleHashError::OutputTooLong)?;
        let (reader, _cleanup) = self.finish(bits)?;
        reader.secret(output).map(TupleHashSecretOutput::new)
    }
}
pub(super) fn bytes_input(bytes: &[u8]) -> Result<Fips202BitString<'_>, TupleHashError> {
    crate::core_state::byte_string(bytes)
}
pub(super) const fn byte_valid(length: usize) -> u8 {
    if length == 0 { 0 } else { 8 }
}
fn read(bytes: &[u8; 16]) -> u128 {
    let mut value = 0_u128;
    for byte in bytes.iter().rev() {
        value = (value << 8) | u128::from(*byte);
    }
    value
}
fn write(bytes: &mut [u8; 16], mut value: u128) -> Result<(), TupleHashError> {
    for byte in bytes {
        *byte = u8::try_from(value & u128::from(u8::MAX))
            .map_err(|_| TupleHashError::MessageTooLong)?;
        value >>= 8;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
