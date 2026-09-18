use super::{
    backend::Reader,
    core_state::{Guard, Metadata},
};
use crate::{Fips202Output, KmacError, KmacSecretOutput};
use brynja_core::clear_owned_region;

// Only reference-bearing reader/cleanup handles move; sponge and metadata stay
// in the caller's workspace until its independent outer guards clear them.
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
    pub(super) fn public(&mut self, output: &mut [u8]) -> Result<(), KmacError> {
        let mut operation = Operation {
            reader: &mut self.reader,
            metadata: &mut *self.cleanup.0,
            complete: false,
        };
        operation
            .reader
            .as_mut()
            .ok_or(KmacError::StateConsumed)?
            .public(output)?;
        operation.complete = true;
        Ok(())
    }
    pub(super) fn secret<'out>(
        &mut self,
        output: &'out mut [u8],
    ) -> Result<KmacSecretOutput<'out>, KmacError> {
        // Also cover a reader already terminated by an earlier operation.
        let _ = clear_owned_region(output);
        let mut operation = Operation {
            reader: &mut self.reader,
            metadata: &mut *self.cleanup.0,
            complete: false,
        };
        let secret = operation
            .reader
            .as_mut()
            .ok_or(KmacError::StateConsumed)?
            .secret(output)?;
        operation.complete = true;
        Ok(KmacSecretOutput::new(secret))
    }
    pub(super) fn final_public(mut self, output: &mut [u8], valid: u8) -> Result<(), KmacError> {
        let reader = self.reader.take().ok_or(KmacError::StateConsumed)?;
        reader.final_public(
            Fips202Output::new(output, valid).map_err(|_| KmacError::InvalidBitString)?,
        )
    }
    pub(super) fn final_secret<'out>(
        mut self,
        output: &'out mut [u8],
        valid: u8,
    ) -> Result<KmacSecretOutput<'out>, KmacError> {
        let _ = clear_owned_region(output);
        let reader = self.reader.take().ok_or(KmacError::StateConsumed)?;
        Fips202Output::new(output, valid).map_err(|_| KmacError::InvalidBitString)?;
        reader
            .final_secret(output, valid)
            .map(KmacSecretOutput::new)
    }
}

#[cfg(test)]
mod tests;
