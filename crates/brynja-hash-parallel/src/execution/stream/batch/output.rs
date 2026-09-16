use super::{Collector, Control, Error, Operation, RootError, Stream};
use crate::execution::{Clear, collector::output_length};
use crate::{
    Fips202BitString, ParallelHashPublicDeclassification as Public, ParallelHashSecretOutput,
};
use brynja_core::clear_owned_region;

impl<'workspace, 'worker, 'authority> Stream<'workspace, 'worker, 'authority> {
    /// Consumes fixed public bytes; errors preserve destination and clear scratch.
    pub fn finalize_public(
        self,
        output: &mut [u8],
        scratch: &mut [u8],
        public: Public,
        control: &mut Control<'_>,
    ) -> Result<(), Error> {
        let stage = Clear(scratch);
        let valid = if output.is_empty() { 0 } else { 8 };
        self.finalize_public_bits(
            crate::execution::bits(&[])?,
            output,
            valid,
            stage.0,
            public,
            control,
        )
    }
    /// Adds canonical final input bits, then consumes fixed public output bits.
    pub fn finalize_public_bits(
        mut self,
        tail: Fips202BitString<'_>,
        output: &mut [u8],
        valid: u8,
        scratch: &mut [u8],
        _public: Public,
        control: &mut Control<'_>,
    ) -> Result<(), Error> {
        let stage = Clear(scratch);
        let count = output_length(output.len(), valid)?;
        if stage.0.len() < output.len() {
            return Err(RootError::OutputLength.into());
        }
        Collector::finish_stream(self.finish_input(tail, control)?, count, false)?;
        self.root
            .public(output, valid, stage.0, true)
            .map_err(Error::from)
    }
    /// Consumes fixed secret bytes; all errors erase the complete destination.
    pub fn finalize_secret<'out>(
        self,
        output: &'out mut [u8],
        control: &mut Control<'_>,
    ) -> Result<ParallelHashSecretOutput<'out>, Error> {
        let _ = clear_owned_region(output);
        let valid = if output.is_empty() { 0 } else { 8 };
        self.finalize_secret_bits(crate::execution::bits(&[])?, output, valid, control)
    }
    /// Final input/output bit strings retain canonical exact-length semantics.
    pub fn finalize_secret_bits<'out>(
        mut self,
        tail: Fips202BitString<'_>,
        output: &'out mut [u8],
        valid: u8,
        control: &mut Control<'_>,
    ) -> Result<ParallelHashSecretOutput<'out>, Error> {
        let _ = clear_owned_region(output);
        let count = output_length(output.len(), valid)?;
        Collector::finish_stream(self.finish_input(tail, control)?, count, false)?;
        self.root.secret(output, valid, true).map_err(Error::from)
    }
    /// Borrows an affine XOF reader; forgetting it cannot reopen absorption.
    pub fn finalize_xof<'state>(
        &'state mut self,
        control: &mut Control<'_>,
    ) -> Result<StreamReader<'state, 'workspace, 'worker, 'authority>, Error> {
        self.finalize_xof_bits(crate::execution::bits(&[])?, control)
    }
    /// Adds a canonical final bit tail before exposing an incremental XOF reader.
    pub fn finalize_xof_bits<'state>(
        &'state mut self,
        tail: Fips202BitString<'_>,
        control: &mut Control<'_>,
    ) -> Result<StreamReader<'state, 'workspace, 'worker, 'authority>, Error> {
        let mut guard = Operation {
            stream: self,
            complete: false,
        };
        Collector::finish_stream(guard.stream.finish_input(tail, control)?, 0, true)?;
        guard.complete = true;
        drop(guard);
        Ok(StreamReader { stream: self })
    }
}

/// Exclusive XOF reader retaining the stream and clearing it on abandonment.
/// ```compile_fail
/// use brynja_hash_parallel::execution::batch::StreamReader;
/// fn require<T: Send>() {} require::<StreamReader<'_, '_, '_, '_>>();
/// ```
/// ```compile_fail
/// use brynja_hash_parallel::execution::batch::StreamReader;
/// fn require<T: Sync>() {} require::<StreamReader<'_, '_, '_, '_>>();
/// ```
/// ```compile_fail
/// use brynja_hash_parallel::execution::batch::StreamReader;
/// fn require<T: Copy>() {} require::<StreamReader<'_, '_, '_, '_>>();
/// ```
/// ```compile_fail
/// use brynja_hash_parallel::execution::batch::StreamReader;
/// fn require<T: Clone>() {} require::<StreamReader<'_, '_, '_, '_>>();
/// ```
/// ```compile_fail
/// use brynja_hash_parallel::execution::batch::StreamReader;
/// fn require<T: core::fmt::Debug>() {} require::<StreamReader<'_, '_, '_, '_>>();
/// ```
pub struct StreamReader<'state, 'workspace, 'worker, 'authority> {
    stream: &'state mut Stream<'workspace, 'worker, 'authority>,
}
impl StreamReader<'_, '_, '_, '_> {
    /// Actual completed leaves, never an advertised width or thread count.
    #[must_use]
    pub fn merged_leaves(&self) -> u128 {
        self.stream.merged_leaves()
    }
    /// Completed leaves that participated in at least one vector call.
    #[must_use]
    pub fn accelerated_leaves(&self) -> u128 {
        self.stream.accelerated_leaves()
    }
    /// Transfers full bytes into a clearing secret output owner.
    pub fn squeeze_secret<'out>(
        &mut self,
        output: &'out mut [u8],
    ) -> Result<ParallelHashSecretOutput<'out>, Error> {
        let mut guard = Operation {
            stream: self.stream,
            complete: false,
        };
        let owned =
            guard
                .stream
                .root
                .secret(output, if output.is_empty() { 0 } else { 8 }, false)?;
        guard.complete = true;
        Ok(owned)
    }
    /// Explicitly declassifies bytes with transactional, fully cleared scratch.
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
    /// Consumes the reader into canonical final secret bits.
    pub fn squeeze_final_secret(
        self,
        output: &mut [u8],
        valid: u8,
    ) -> Result<ParallelHashSecretOutput<'_>, Error> {
        self.stream
            .root
            .secret(output, valid, true)
            .map_err(Error::from)
    }
    /// Consumes final public bits; failure preserves output and clears scratch.
    pub fn squeeze_final_public(
        self,
        output: &mut [u8],
        valid: u8,
        scratch: &mut [u8],
        _public: Public,
    ) -> Result<(), Error> {
        self.stream
            .root
            .public(output, valid, scratch, true)
            .map_err(Error::from)
    }
}
impl Drop for StreamReader<'_, '_, '_, '_> {
    fn drop(&mut self) {
        self.stream.cancel();
    }
}
