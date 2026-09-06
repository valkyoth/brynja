use super::{Sha1BackendError, Sha1BackendSession};
use crate::{BitString, engine, owner::Sha1Owner};

/// Consuming, non-cloneable accelerated SHA-1 for PUBLIC legacy data only.
///
/// This type does not implement the sealed hardened capability. Backend-local
/// vector schedules/registers/spills have no cleanup qualification. Its owned
/// buffers clear on Drop, but that does not make it suitable for secrets.
/// A backend failure latches the operation and clears the owned state.
/// ```compile_fail
/// fn hardened<T: brynja_legacy_sha1::HardenedSha1State>() {}
/// hardened::<brynja_legacy_sha1::AcceleratedSha1<'static>>();
/// ```
pub struct AcceleratedSha1<'session> {
    owner: Sha1Owner,
    session: &'session Sha1BackendSession,
    failed: bool,
}

#[cfg(test)]
mod tests;

impl<'session> AcceleratedSha1<'session> {
    /// Starts an empty public-data operation after health/feature revalidation.
    pub fn new(session: &'session Sha1BackendSession) -> Result<Self, Sha1BackendError> {
        session.ensure_healthy()?;
        Ok(Self {
            owner: Sha1Owner::new(),
            session,
            failed: false,
        })
    }

    /// Complete message bits accepted; zero after terminal backend failure.
    pub fn message_bits(&self) -> u64 {
        self.owner.bits()
    }

    /// Checks remaining bit capacity without state mutation.
    pub fn check_additional_bits(&self, bits: u64) -> Result<(), Sha1BackendError> {
        if self.failed {
            return Err(Sha1BackendError::Quarantined);
        }
        engine::admit_bits(self.owner.bits(), bits)
            .map(|_| ())
            .map_err(|_| Sha1BackendError::MessageTooLong)
    }

    /// Checks byte capacity without state mutation.
    pub fn check_additional_bytes(&self, bytes: usize) -> Result<(), Sha1BackendError> {
        if self.failed {
            return Err(Sha1BackendError::Quarantined);
        }
        engine::admit_bytes(self.owner.bits(), bytes)
            .map(|_| ())
            .map_err(|_| Sha1BackendError::MessageTooLong)
    }

    /// Absorbs bytes. Length rejection is atomic; backend failure is terminal.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Sha1BackendError> {
        self.ready()?;
        let total = engine::admit_bytes(self.owner.bits(), input.len())
            .map_err(|_| Sha1BackendError::MessageTooLong)?;
        for byte in input {
            let offset = self.owner.buffered();
            assert!(offset < 64, "SHA-1 accelerated update offset invariant");
            if let Some(destination) = self.owner.block.get_mut(offset) {
                *destination = *byte;
            }
            let [count] = &mut self.owner.buffered;
            *count = count.saturating_add(1);
            if self.owner.buffered() == 64 {
                self.compress()?;
            }
        }
        self.owner.message_length = total.to_be_bytes();
        Ok(())
    }

    /// Consumes the state and returns the public digest; no output on failure.
    pub fn finalize(mut self) -> Result<[u8; 20], Sha1BackendError> {
        self.ready()?;
        self.finish(None, self.owner.bits())
    }

    /// Consumes a canonical final MSB-first bit string; cannot append afterwards.
    pub fn finalize_bits(mut self, tail: BitString<'_>) -> Result<[u8; 20], Sha1BackendError> {
        self.ready()?;
        let bits = u64::try_from(tail.bit_len()).map_err(|_| Sha1BackendError::MessageTooLong)?;
        let total = engine::admit_bits(self.owner.bits(), bits)
            .map_err(|_| Sha1BackendError::MessageTooLong)?;
        let (bytes, partial) = tail.split();
        self.update(bytes)?;
        self.finish(partial, total)
    }

    /// Hashes one complete public byte message with the selected session.
    pub fn hash(
        session: &'session Sha1BackendSession,
        input: &[u8],
    ) -> Result<[u8; 20], Sha1BackendError> {
        let mut state = Self::new(session)?;
        state.update(input)?;
        state.finalize()
    }

    /// Hashes one complete canonical public bit message with this session.
    pub fn hash_bits(
        session: &'session Sha1BackendSession,
        input: BitString<'_>,
    ) -> Result<[u8; 20], Sha1BackendError> {
        Self::new(session)?.finalize_bits(input)
    }

    fn ready(&mut self) -> Result<(), Sha1BackendError> {
        if self.failed {
            return Err(Sha1BackendError::Quarantined);
        }
        if let Err(error) = self.session.ensure_healthy() {
            return self.fail(error);
        }
        Ok(())
    }

    fn fail<T>(&mut self, error: Sha1BackendError) -> Result<T, Sha1BackendError> {
        self.failed = true;
        self.owner.wipe();
        Err(error)
    }

    fn compress(&mut self) -> Result<(), Sha1BackendError> {
        self.ready()?;
        let mut words = [0; 5];
        for (word, bytes) in words
            .iter_mut()
            .zip(self.owner.chaining_state.chunks_exact(4))
        {
            if let [a, b, c, d] = bytes {
                *word = u32::from_be_bytes([*a, *b, *c, *d]);
            }
        }
        if let Err(error) = self.session.compress(&mut words, &self.owner.block) {
            return self.fail(error);
        }
        for (word, bytes) in words
            .into_iter()
            .zip(self.owner.chaining_state.chunks_exact_mut(4))
        {
            bytes.copy_from_slice(&word.to_be_bytes());
        }
        self.owner.clear_block();
        Ok(())
    }

    fn finish(
        &mut self,
        partial: Option<(u8, u8)>,
        total: u64,
    ) -> Result<[u8; 20], Sha1BackendError> {
        self.ready()?;
        let (last, valid) = partial.unwrap_or((0, 0));
        let offset = self.owner.buffered();
        assert!(offset < 64, "SHA-1 accelerated padding offset invariant");
        if let Some(destination) = self.owner.block.get_mut(offset) {
            *destination = last | (0x80_u8 >> valid);
        }
        if offset >= 56 {
            self.compress()?;
        }
        for (destination, shift) in self
            .owner
            .block
            .iter_mut()
            .skip(56)
            .zip([56, 48, 40, 32, 24, 16, 8, 0])
        {
            *destination = u8::try_from((total >> shift) & 0xff).unwrap_or(0);
        }
        self.compress()?;
        Ok(self.owner.chaining_state)
    }
}
