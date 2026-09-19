use super::{
    backend::{Reader, State},
    core_state::{read, write},
};
use crate::{
    Fips202Output, ParallelHashError as Error, ParallelHashSecretOutput,
    secret_encoding::SecretEncodedInteger as Encoded,
};
use brynja_core::clear_owned_region;

pub(super) struct Count {
    merged: [u8; 16],
}
impl Count {
    pub(super) const fn new() -> Self {
        Self { merged: [0; 16] }
    }
    pub(super) fn wipe(&mut self) {
        let _ = clear_owned_region(&mut self.merged);
    }
    #[cfg(test)]
    pub(super) fn cleared(&self) -> bool {
        self.merged == [0; 16]
    }
}
impl Drop for Count {
    fn drop(&mut self) {
        self.wipe();
    }
}
pub(super) struct CountGuard<'scope>(pub(super) &'scope mut Count);
impl Drop for CountGuard<'_> {
    fn drop(&mut self) {
        self.0.wipe();
    }
}

pub(super) struct Root<'scope, S: State> {
    state: Option<S>,
    count: &'scope mut Count,
    expected: u128,
}
struct Operation<'borrow, 'scope, S: State> {
    collector: &'borrow mut Root<'scope, S>,
    complete: bool,
}
impl<S: State> Drop for Operation<'_, '_, S> {
    fn drop(&mut self) {
        if !self.complete {
            self.collector.cancel();
        }
    }
}
impl<'scope, S: State> Root<'scope, S> {
    pub(super) fn new(
        state: S,
        count: &'scope mut Count,
        block: usize,
        expected: u128,
    ) -> Result<Self, Error> {
        count.wipe();
        let mut collector = Self {
            state: Some(state),
            count,
            expected,
        };
        if block == 0 {
            return Err(Error::InvalidBlockSize);
        }
        let mut prefix = Encoded::empty();
        prefix.left(u128::try_from(block).map_err(|_| Error::InvalidBlockSize)?)?;
        collector.root()?.update(prefix.bytes()?)?;
        Ok(collector)
    }
    fn root(&mut self) -> Result<&mut S, Error> {
        self.state.as_mut().ok_or(Error::StateConsumed)
    }
    pub(super) fn merge(&mut self, index: Result<u128, Error>, bytes: &[u8]) -> Result<(), Error> {
        let mut guard = Operation {
            collector: self,
            complete: false,
        };
        guard.collector.root()?.check()?;
        let index = index?;
        if index != read(&guard.collector.count.merged) || index >= guard.collector.expected {
            return Err(Error::LeafOrder);
        }
        let next = index.checked_add(1).ok_or(Error::MessageTooLong)?;
        guard.collector.root()?.update(bytes)?;
        write(&mut guard.collector.count.merged, next)?;
        guard.complete = true;
        Ok(())
    }
    fn finish(&mut self, bits: u128) -> Result<S::Reader, Error> {
        self.root()?.check()?;
        if read(&self.count.merged) != self.expected {
            return Err(Error::LeafOrder);
        }
        let mut suffix = Encoded::empty();
        suffix.right(self.expected)?;
        self.root()?.update(suffix.bytes()?)?;
        suffix.right(bits)?;
        self.root()?.update(suffix.bytes()?)?;
        self.state.take().ok_or(Error::StateConsumed)?.finish()
    }
    pub(super) fn public(mut self, output: &mut [u8], valid: u8) -> Result<(), Error> {
        let destination = Fips202Output::new(output, valid).map_err(|_| Error::InvalidBitString)?;
        let bits = u128::try_from(destination.bit_len()).map_err(|_| Error::OutputTooLong)?;
        self.finish(bits)?.public(destination)
    }
    pub(super) fn secret<'out>(
        mut self,
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
        self.finish(bits)?
            .secret(output, valid)
            .map(ParallelHashSecretOutput::new)
    }
    pub(super) fn xof(mut self) -> Result<S::Reader, Error> {
        self.finish(0)
    }
    fn cancel(&mut self) {
        self.state = None;
        self.count.wipe();
    }
}
impl<S: State> Drop for Root<'_, S> {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[cfg(test)]
mod tests;
