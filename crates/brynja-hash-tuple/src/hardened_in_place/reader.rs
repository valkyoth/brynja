use super::{
    backend::Reader,
    core_state::{Guard, Metadata},
};
use crate::{Fips202Output, TupleHashError, TupleHashSecretOutput};
use brynja_core::clear_owned_region;

// Only borrowed handles move. The outer scope independently clears storage
// even if this handle is forgotten; operation guards cover errors and unwind.
pub(super) struct Output<'scope, R: Reader> {
    reader: Option<R>,
    cleanup: Guard<'scope>,
}
struct Operation<'borrow, R: Reader> {
    reader: &'borrow mut Option<R>,
    metadata: &'borrow mut Metadata,
    complete: bool,
}
impl<R: Reader> Drop for Operation<'_, R> {
    fn drop(&mut self) {
        if !self.complete {
            *self.reader = None;
            self.metadata.wipe();
        }
    }
}
impl<'scope, R: Reader> Output<'scope, R> {
    pub(super) fn new(reader: R, cleanup: Guard<'scope>) -> Self {
        Self {
            reader: Some(reader),
            cleanup,
        }
    }
    pub(super) fn public(&mut self, output: &mut [u8]) -> Result<(), TupleHashError> {
        let mut guard = Operation {
            reader: &mut self.reader,
            metadata: &mut *self.cleanup.0,
            complete: false,
        };
        guard
            .reader
            .as_mut()
            .ok_or(TupleHashError::StateConsumed)?
            .read_public(output)?;
        guard.complete = true;
        Ok(())
    }
    pub(super) fn secret<'out>(
        &mut self,
        output: &'out mut [u8],
    ) -> Result<TupleHashSecretOutput<'out>, TupleHashError> {
        let _ = clear_owned_region(output);
        let mut guard = Operation {
            reader: &mut self.reader,
            metadata: &mut *self.cleanup.0,
            complete: false,
        };
        let secret = guard
            .reader
            .as_mut()
            .ok_or(TupleHashError::StateConsumed)?
            .read_secret(output)?;
        guard.complete = true;
        Ok(TupleHashSecretOutput::new(secret))
    }
    pub(super) fn final_public(
        mut self,
        output: &mut [u8],
        valid: u8,
    ) -> Result<(), TupleHashError> {
        let reader = self.reader.take().ok_or(TupleHashError::StateConsumed)?;
        reader.public(
            Fips202Output::new(output, valid).map_err(|_| TupleHashError::InvalidBitString)?,
        )
    }
    pub(super) fn final_secret<'out>(
        mut self,
        output: &'out mut [u8],
        valid: u8,
    ) -> Result<TupleHashSecretOutput<'out>, TupleHashError> {
        let _ = clear_owned_region(output);
        let reader = self.reader.take().ok_or(TupleHashError::StateConsumed)?;
        reader
            .secret(
                Fips202Output::new(output, valid).map_err(|_| TupleHashError::InvalidBitString)?,
            )
            .map(TupleHashSecretOutput::new)
    }
}

#[cfg(test)]
mod tests;
