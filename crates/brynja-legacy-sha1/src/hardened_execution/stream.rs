use super::{Error, Executor, begin_output, empty, engine};
use crate::{BitString, HardenedSha1State, PublicDeclassification, Sha1Error, owner::Sha1Owner};
use brynja_core::OwnedSecretRegion;

/// Affine secret-bearing stream. No clone, reset, raw state, ordinary conversion,
/// length/capacity query, Send, Sync, Copy or Debug is exposed. This is not a
/// length-hiding primitive: work and actual-input errors can depend on length.
pub struct Stream<'a> {
    pub(super) executor: &'a Executor,
    pub(super) owner: Sha1Owner,
    failed: bool,
}
impl crate::hardened::sealed::Sealed for Stream<'_> {}
impl HardenedSha1State for Stream<'_> {}

impl<'a> Stream<'a> {
    pub(super) fn new(executor: &'a Executor) -> Self {
        Self {
            executor,
            owner: Sha1Owner::new(),
            failed: false,
        }
    }
    fn ready(&self) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Quarantined);
        }
        self.executor.ready()
    }
    /// Length rejection is atomic. Authority/invariant errors or unwind destroy
    /// state and quarantine the executor; they never authorize portable fallback.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        // Install the cleanup guard before calling a platform callback.
        let mut operation = Operation {
            state: self,
            completed: false,
        };
        operation.state.ready()?;
        if let Err(error) = crate::engine::admit_bytes(operation.state.owner.bits(), input.len()) {
            operation.completed = true;
            return Err(error.into());
        }
        engine::update(&mut operation.state.owner, input, operation.state.executor)?;
        operation.completed = true;
        Ok(())
    }
    pub(super) fn finish(&mut self, tail: BitString<'_>) -> Result<(), Error> {
        let mut operation = Operation {
            state: self,
            completed: false,
        };
        operation.state.ready()?;
        let bits = u64::try_from(tail.bit_len()).map_err(|_| Sha1Error::MessageTooLong)?;
        if let Err(error) = crate::engine::admit_bits(operation.state.owner.bits(), bits) {
            operation.completed = true;
            return Err(error.into());
        }
        engine::finish(&mut operation.state.owner, tail, operation.state.executor)?;
        operation.completed = true;
        Ok(())
    }
    /// Consumes this stream and explicitly declassifies a 20-byte digest.
    /// Every error leaves the public destination unchanged.
    pub fn finalize_public(
        self,
        destination: &mut [u8],
        public: PublicDeclassification,
    ) -> Result<(), Error> {
        self.finalize_bits_public(empty()?, destination, public)
    }
    /// Consumes an arbitrary-bit tail and explicitly releases public output.
    pub fn finalize_bits_public(
        mut self,
        tail: BitString<'_>,
        destination: &mut [u8],
        _public: PublicDeclassification,
    ) -> Result<(), Error> {
        if destination.len() != 20 {
            return Err(Sha1Error::OutputLength.into());
        }
        self.finish(tail)?;
        destination.copy_from_slice(&self.owner.output_staging);
        Ok(())
    }
    /// Consuming typed secret output; failure and unwind clear all supplied bytes.
    pub fn finalize_secret(
        mut self,
        destination: &mut [u8],
    ) -> Result<OwnedSecretRegion<'_>, Error> {
        let mut output = begin_output(destination)?;
        self.finish(empty()?)?;
        output
            .write(&self.owner.output_staging)
            .map_err(|_| Sha1Error::SecretMemory)?;
        output.finish().map_err(|_| Sha1Error::SecretMemory.into())
    }
    /// Consuming bit-tail output; no partial byte can be followed by another update.
    pub fn finalize_bits_secret<'out>(
        mut self,
        tail: BitString<'_>,
        destination: &'out mut [u8],
    ) -> Result<OwnedSecretRegion<'out>, Error> {
        let mut output = begin_output(destination)?;
        self.finish(tail)?;
        output
            .write(&self.owner.output_staging)
            .map_err(|_| Sha1Error::SecretMemory)?;
        output.finish().map_err(|_| Sha1Error::SecretMemory.into())
    }
    /// Consumes the stream; the six source-owned regions clear through Drop.
    pub fn cancel(self) {}
}

struct Operation<'s, 'a> {
    state: &'s mut Stream<'a>,
    completed: bool,
}
impl Drop for Operation<'_, '_> {
    fn drop(&mut self) {
        if !self.completed {
            self.state.owner.wipe();
            self.state.failed = true;
            self.state.executor.quarantine();
        }
    }
}

#[cfg(test)]
mod tests;
