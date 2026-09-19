use super::backend::{Reader, State};
use crate::{
    Fips202BitString, Fips202Output, ParallelHashError as Error, ParallelHashSecretOutput,
    secret_encoding::SecretEncodedInteger,
};
use brynja_core::clear_owned_region;

pub(super) struct Metadata {
    used: [u8; 16],
    leaves: [u8; 16],
    leaf: [u8; 64],
}
impl Metadata {
    pub(super) const fn new() -> Self {
        Self {
            used: [0; 16],
            leaves: [0; 16],
            leaf: [0; 64],
        }
    }
    pub(super) fn wipe(&mut self) {
        let _ = clear_owned_region(&mut self.used);
        let _ = clear_owned_region(&mut self.leaves);
        let _ = clear_owned_region(&mut self.leaf);
    }
    #[cfg(test)]
    pub(super) fn cleared(&self) -> bool {
        self.used == [0; 16] && self.leaves == [0; 16] && self.leaf == [0; 64]
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
pub(super) struct Block<'scope>(pub(super) &'scope mut [u8]);
impl Drop for Block<'_> {
    fn drop(&mut self) {
        let _ = clear_owned_region(self.0);
    }
}

pub(super) struct Core<'scope, S: State> {
    state: Option<S>,
    metadata: &'scope mut Metadata,
    block: &'scope mut [u8],
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
    pub(super) fn new(
        state: S,
        metadata: &'scope mut Metadata,
        block: &'scope mut [u8],
    ) -> Result<Self, Error> {
        metadata.wipe();
        let _ = clear_owned_region(block);
        let mut core = Self {
            state: Some(state),
            metadata,
            block,
        };
        if core.block.is_empty() {
            return Err(Error::InvalidBlockSize);
        }
        let mut prefix = SecretEncodedInteger::empty();
        prefix.left(u128::try_from(core.block.len()).map_err(|_| Error::InvalidBlockSize)?)?;
        core.root()?.update(prefix.bytes()?)?;
        Ok(core)
    }
    fn root(&mut self) -> Result<&mut S, Error> {
        self.state.as_mut().ok_or(Error::StateConsumed)
    }
    fn used(&self) -> Result<usize, Error> {
        let used = usize::try_from(read(&self.metadata.used)).map_err(|_| Error::StateConsumed)?;
        if used >= self.block.len() {
            return Err(Error::StateConsumed);
        }
        Ok(used)
    }
    fn set_used(&mut self, used: usize) -> Result<(), Error> {
        let value = u128::try_from(used).map_err(|_| Error::MessageTooLong)?;
        write(&mut self.metadata.used, value)
    }
    pub(super) fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        let mut operation = Operation {
            core: self,
            complete: false,
        };
        operation.core.root()?.check()?;
        operation.core.update_inner(input)?;
        operation.complete = true;
        Ok(())
    }
    fn update_inner(&mut self, mut input: &[u8]) -> Result<(), Error> {
        let full = self
            .used()?
            .checked_add(input.len())
            .and_then(|v| v.checked_div(self.block.len()))
            .ok_or(Error::MessageTooLong)?;
        read(&self.metadata.leaves)
            .checked_add(u128::try_from(full).map_err(|_| Error::MessageTooLong)?)
            .ok_or(Error::MessageTooLong)?;
        while !input.is_empty() {
            let used = self.used()?;
            let available = self
                .block
                .len()
                .checked_sub(used)
                .ok_or(Error::StateConsumed)?;
            let take = available.min(input.len());
            let end = used.checked_add(take).ok_or(Error::MessageTooLong)?;
            brynja_core::copy_secret_region(
                self.block.get_mut(used..end).ok_or(Error::StateConsumed)?,
                input.get(..take).ok_or(Error::StateConsumed)?,
            )
            .map_err(|_| Error::StateConsumed)?;
            self.set_used(end)?;
            input = input.get(take..).ok_or(Error::StateConsumed)?;
            if end == self.block.len() {
                self.flush(8)?;
            }
        }
        Ok(())
    }
    fn flush(&mut self, valid: u8) -> Result<(), Error> {
        let used = usize::try_from(read(&self.metadata.used)).map_err(|_| Error::StateConsumed)?;
        if used == 0 || used > self.block.len() {
            return Err(Error::StateConsumed);
        }
        let count = read(&self.metadata.leaves)
            .checked_add(1)
            .ok_or(Error::MessageTooLong)?;
        let bits =
            Fips202BitString::new(self.block.get(..used).ok_or(Error::StateConsumed)?, valid)
                .map_err(|_| Error::InvalidBitString)?;
        let state = self.state.as_mut().ok_or(Error::StateConsumed)?;
        let secret = state.leaf(bits, &mut self.metadata.leaf)?;
        state.update(secret.expose())?;
        drop(secret);
        let _ = clear_owned_region(self.block);
        let _ = clear_owned_region(&mut self.metadata.used);
        write(&mut self.metadata.leaves, count)
    }
    fn finish_input(&mut self, tail: Fips202BitString<'_>) -> Result<(), Error> {
        self.root()?.check()?;
        let input = tail.as_bytes();
        if tail.is_byte_aligned() {
            self.update_inner(input)?;
        } else {
            let complete = input.len().checked_sub(1).ok_or(Error::InvalidBitString)?;
            self.update_inner(input.get(..complete).ok_or(Error::InvalidBitString)?)?;
            let used = self.used()?;
            let end = used.checked_add(1).ok_or(Error::MessageTooLong)?;
            brynja_core::copy_secret_region(
                self.block.get_mut(used..end).ok_or(Error::StateConsumed)?,
                input.get(complete..).ok_or(Error::InvalidBitString)?,
            )
            .map_err(|_| Error::StateConsumed)?;
            self.set_used(end)?;
            return self.flush(tail.valid_bits_in_last_byte());
        }
        if self.used()? != 0 {
            self.flush(8)?;
        }
        Ok(())
    }
    fn finish(
        &mut self,
        tail: Fips202BitString<'_>,
        output_bits: u128,
    ) -> Result<S::Reader, Error> {
        self.finish_input(tail)?;
        let mut suffix = SecretEncodedInteger::empty();
        suffix.right(read(&self.metadata.leaves))?;
        self.root()?.update(suffix.bytes()?)?;
        suffix.right(output_bits)?;
        self.root()?.update(suffix.bytes()?)?;
        self.state.take().ok_or(Error::StateConsumed)?.finish()
    }
    pub(super) fn finish_xof(mut self, tail: Fips202BitString<'_>) -> Result<S::Reader, Error> {
        // Only the sponge borrow leaves; Core::drop clears leaf/block metadata
        // before the first squeeze. The outer scope also handles forgotten readers.
        self.finish(tail, 0)
    }
    pub(super) fn public(
        mut self,
        tail: Fips202BitString<'_>,
        output: &mut [u8],
        valid: u8,
    ) -> Result<(), Error> {
        let destination = Fips202Output::new(output, valid).map_err(|_| Error::InvalidBitString)?;
        let bits = u128::try_from(destination.bit_len()).map_err(|_| Error::OutputTooLong)?;
        self.finish(tail, bits)?.public(destination)
    }
    pub(super) fn secret<'out>(
        mut self,
        tail: Fips202BitString<'_>,
        output: &'out mut [u8],
        valid: u8,
    ) -> Result<ParallelHashSecretOutput<'out>, Error> {
        let _ = clear_owned_region(output);
        let bits = u128::try_from(
            Fips202Output::new(output, valid)
                .map_err(|_| Error::InvalidBitString)?
                .bit_len(),
        )
        .map_err(|_| Error::OutputTooLong)?;
        self.finish(tail, bits)?
            .secret(output, valid)
            .map(ParallelHashSecretOutput::new)
    }
    fn cancel(&mut self) {
        self.state = None;
        self.metadata.wipe();
        let _ = clear_owned_region(self.block);
    }
}
impl<S: State> Drop for Core<'_, S> {
    fn drop(&mut self) {
        self.cancel();
    }
}
pub(super) fn write(bytes: &mut [u8; 16], value: u128) -> Result<(), Error> {
    for (index, byte) in bytes.iter_mut().enumerate() {
        let shift = index.checked_mul(8).ok_or(Error::MessageTooLong)?;
        *byte = u8::try_from((value >> shift) & 255).map_err(|_| Error::MessageTooLong)?;
    }
    Ok(())
}
pub(super) fn read(bytes: &[u8; 16]) -> u128 {
    bytes.iter().enumerate().fold(0, |value, (index, byte)| {
        value | (u128::from(*byte) << index.saturating_mul(8))
    })
}

#[cfg(test)]
mod tests;
