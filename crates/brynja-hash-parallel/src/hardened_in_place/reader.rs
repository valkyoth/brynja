use super::backend::Reader;
use crate::{Fips202Output, ParallelHashError as Error, ParallelHashSecretOutput};
use brynja_core::clear_owned_region;

// Absorption's counters, leaf output and block are already cleared. This owns
// only a borrowed sponge handle; the independent outer scope covers forget.
pub(super) struct Output<R: Reader> {
    reader: Option<R>,
}
struct Operation<'borrow, R: Reader> {
    reader: &'borrow mut Option<R>,
    complete: bool,
}
impl<R: Reader> Drop for Operation<'_, R> {
    fn drop(&mut self) {
        if !self.complete {
            *self.reader = None;
        }
    }
}
impl<R: Reader> Output<R> {
    pub(super) fn new(reader: R) -> Self {
        Self {
            reader: Some(reader),
        }
    }
    pub(super) fn public(&mut self, output: &mut [u8]) -> Result<(), Error> {
        let mut guard = Operation {
            reader: &mut self.reader,
            complete: false,
        };
        guard
            .reader
            .as_mut()
            .ok_or(Error::StateConsumed)?
            .read_public(output)?;
        guard.complete = true;
        Ok(())
    }
    pub(super) fn secret<'out>(
        &mut self,
        output: &'out mut [u8],
    ) -> Result<ParallelHashSecretOutput<'out>, Error> {
        let _ = clear_owned_region(output);
        let mut guard = Operation {
            reader: &mut self.reader,
            complete: false,
        };
        let secret = guard
            .reader
            .as_mut()
            .ok_or(Error::StateConsumed)?
            .read_secret(output)?;
        guard.complete = true;
        Ok(ParallelHashSecretOutput::new(secret))
    }
    pub(super) fn final_public(mut self, output: &mut [u8], valid: u8) -> Result<(), Error> {
        let reader = self.reader.take().ok_or(Error::StateConsumed)?;
        reader.public(Fips202Output::new(output, valid).map_err(|_| Error::InvalidBitString)?)
    }
    pub(super) fn final_secret<'out>(
        mut self,
        output: &'out mut [u8],
        valid: u8,
    ) -> Result<ParallelHashSecretOutput<'out>, Error> {
        let _ = clear_owned_region(output);
        let reader = self.reader.take().ok_or(Error::StateConsumed)?;
        Fips202Output::new(output, valid).map_err(|_| Error::InvalidBitString)?;
        reader
            .secret(output, valid)
            .map(ParallelHashSecretOutput::new)
    }
}

#[cfg(test)]
mod tests;
