use super::{Clear, Error, Mode, Stream, collector::output_length, stream::Operation};
use crate::{
    Fips202BitString, ParallelHashPublicDeclassification as Public, ParallelHashSecretOutput,
};
use brynja_core::clear_owned_region;

impl<'workspace, 'authority> Stream<'workspace, 'authority> {
    /// Consumes the stream into fixed public bytes, clearing scratch on every exit.
    pub fn finalize_public<'worker>(
        self,
        output: &mut [u8],
        scratch: &mut [u8],
        public: Public,
        select: impl FnMut(u128) -> Result<Mode<'worker>, Error>,
    ) -> Result<(), Error> {
        let stage = Clear(scratch);
        let valid = if output.is_empty() { 0 } else { 8 };
        self.finalize_public_bits(super::bits(&[])?, output, valid, stage.0, public, select)
    }
    /// Adds a canonical final bit string and consumes fixed public output bits.
    /// Invalid lengths and callback failures preserve output and erase scratch.
    pub fn finalize_public_bits<'worker>(
        mut self,
        tail: Fips202BitString<'_>,
        output: &mut [u8],
        valid: u8,
        scratch: &mut [u8],
        _public: Public,
        select: impl FnMut(u128) -> Result<Mode<'worker>, Error>,
    ) -> Result<(), Error> {
        let stage = Clear(scratch);
        let count = output_length(output.len(), valid)?;
        if stage.0.len() < output.len() {
            return Err(Error::OutputLength);
        }
        self.finish_input(tail, select)?;
        self.root.finish(count, false)?;
        self.root.public(output, valid, stage.0, true)
    }
    /// Consumes fixed secret bytes. Every error clears the complete destination.
    pub fn finalize_secret<'out, 'worker>(
        self,
        output: &'out mut [u8],
        select: impl FnMut(u128) -> Result<Mode<'worker>, Error>,
    ) -> Result<ParallelHashSecretOutput<'out>, Error> {
        let _ = clear_owned_region(output);
        let valid = if output.is_empty() { 0 } else { 8 };
        self.finalize_secret_bits(super::bits(&[])?, output, valid, select)
    }
    /// Adds canonical final input bits and transfers clearing output ownership.
    pub fn finalize_secret_bits<'out, 'worker>(
        mut self,
        tail: Fips202BitString<'_>,
        output: &'out mut [u8],
        valid: u8,
        select: impl FnMut(u128) -> Result<Mode<'worker>, Error>,
    ) -> Result<ParallelHashSecretOutput<'out>, Error> {
        let _ = clear_owned_region(output);
        let count = output_length(output.len(), valid)?;
        self.finish_input(tail, select)?;
        self.root.finish(count, false)?;
        self.root.secret(output, valid, true)
    }
    /// Closes byte input and borrows an incremental XOF reader in place.
    pub fn finalize_xof<'state, 'worker>(
        &'state mut self,
        select: impl FnMut(u128) -> Result<Mode<'worker>, Error>,
    ) -> Result<StreamReader<'state, 'workspace, 'authority>, Error> {
        self.finalize_xof_bits(super::bits(&[])?, select)
    }
    /// Adds a canonical final input tail. Forgotten readers cannot reopen input.
    pub fn finalize_xof_bits<'state, 'worker>(
        &'state mut self,
        tail: Fips202BitString<'_>,
        select: impl FnMut(u128) -> Result<Mode<'worker>, Error>,
    ) -> Result<StreamReader<'state, 'workspace, 'authority>, Error> {
        let mut guard = Operation {
            stream: self,
            complete: false,
        };
        guard.stream.finish_input(tail, select)?;
        guard.stream.root.finish(0, true)?;
        // End the guard loan before returning the affine reader. Success remains
        // terminal for absorption and the reader owns cancellation on abandonment.
        guard.complete = true;
        drop(guard);
        Ok(StreamReader { stream: self })
    }
}

/// Exclusive streaming XOF reader; Drop clears its retained root and workspace.
pub struct StreamReader<'state, 'workspace, 'authority> {
    stream: &'state mut Stream<'workspace, 'authority>,
}
impl StreamReader<'_, '_, '_> {
    /// Transfers full bytes into a clearing secret owner.
    pub fn squeeze_secret<'out>(
        &mut self,
        output: &'out mut [u8],
    ) -> Result<ParallelHashSecretOutput<'out>, Error> {
        let mut guard = Operation {
            stream: self.stream,
            complete: false,
        };
        let result =
            guard
                .stream
                .root
                .secret(output, if output.is_empty() { 0 } else { 8 }, false)?;
        guard.complete = true;
        Ok(result)
    }
    /// Explicitly declassifies bytes using full-length transactional scratch.
    pub fn squeeze_public(
        &mut self,
        output: &mut [u8],
        scratch: &mut [u8],
        _public: Public,
    ) -> Result<(), Error> {
        let mut guard = Operation {
            stream: self.stream,
            complete: false,
        };
        guard.stream.root.public(
            output,
            if output.is_empty() { 0 } else { 8 },
            scratch,
            false,
        )?;
        guard.complete = true;
        Ok(())
    }
    /// Consumes final canonical secret bits; all errors clear destination.
    pub fn squeeze_final_secret(
        self,
        output: &mut [u8],
        valid: u8,
    ) -> Result<ParallelHashSecretOutput<'_>, Error> {
        self.stream.root.secret(output, valid, true)
    }
    /// Consumes final public bits; failure preserves output and clears scratch.
    pub fn squeeze_final_public(
        self,
        output: &mut [u8],
        valid: u8,
        scratch: &mut [u8],
        _public: Public,
    ) -> Result<(), Error> {
        self.stream.root.public(output, valid, scratch, true)
    }
}
impl Drop for StreamReader<'_, '_, '_> {
    fn drop(&mut self) {
        self.stream.cancel();
    }
}
