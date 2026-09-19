use super::super::{
    Engine, Error, HardenedSha3SecretOutput, KeccakSession, Sha3PublicDeclassification, Stage,
    Storage, begin_secret, clear_owned_region, finish_secret,
};
use crate::{Fips202BitString, sp800185::absorb_cshake_prefix};

pub(super) struct XofStorage<'authority> {
    pub(super) inner: Storage<'authority>,
    domain: [u8; 2],
}
impl<'authority> XofStorage<'authority> {
    pub(super) fn new(session: KeccakSession<'authority>, rate: usize) -> Result<Self, Error> {
        Ok(Self {
            inner: Storage {
                engine: Engine::new(session, rate)?,
                stage: Stage([0; 168]),
            },
            domain: [0; 2],
        })
    }
    pub(super) fn clear(&mut self) {
        self.inner.clear();
        let _ = clear_owned_region(&mut self.domain);
    }
    pub(super) fn restart(&mut self) -> Result<(), Error> {
        self.clear();
        self.inner.engine.restart()?;
        self.domain = [0x1f, 5];
        Ok(())
    }
    pub(super) fn customize(
        &mut self,
        rate: usize,
        n: Fips202BitString<'_>,
        s: Fips202BitString<'_>,
    ) -> Result<(), Error> {
        let mut backend_error = None;
        let customized = absorb_cshake_prefix(rate, n, s, |bytes| {
            self.inner.engine.update(bytes).map_err(|error| {
                backend_error = Some(error);
            })
        })
        .map_err(|()| backend_error.unwrap_or(Error::PrefixEncoding))?;
        self.domain = if customized { [0x04, 3] } else { [0x1f, 5] };
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn cleared_for_test(&self) -> bool {
        self.inner.engine.cleared_for_test()
            && self.inner.stage.0.iter().all(|b| *b == 0)
            && self.domain == [0; 2]
    }
}
impl Drop for XofStorage<'_> {
    fn drop(&mut self) {
        self.clear();
    }
}

pub(super) struct Scope<'scope, 'authority>(pub(super) &'scope mut XofStorage<'authority>);
impl Drop for Scope<'_, '_> {
    fn drop(&mut self) {
        self.0.clear();
    }
}

pub(super) struct Borrowed<'scope, 'authority> {
    pub(super) storage: &'scope mut XofStorage<'authority>,
}
impl Drop for Borrowed<'_, '_> {
    fn drop(&mut self) {
        self.storage.clear();
    }
}

struct Operation<'scope, 'authority> {
    storage: &'scope mut XofStorage<'authority>,
    complete: bool,
}
impl Drop for Operation<'_, '_> {
    fn drop(&mut self) {
        if !self.complete {
            self.storage.clear();
        } else {
            let _ = clear_owned_region(&mut self.storage.inner.stage.0);
        }
    }
}

impl Borrowed<'_, '_> {
    fn run<R>(
        &mut self,
        operation: impl FnOnce(&mut XofStorage<'_>) -> Result<R, Error>,
    ) -> Result<R, Error> {
        let mut guard = Operation {
            storage: &mut *self.storage,
            complete: false,
        };
        let result = operation(guard.storage);
        if result.is_ok() {
            guard.complete = true;
        }
        result
    }
    pub(super) fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        self.run(|storage| storage.inner.engine.update(input))
    }
    pub(super) fn finish(&mut self, input: Fips202BitString<'_>) -> Result<(), Error> {
        self.run(|storage| {
            storage
                .inner
                .engine
                .finish(input, storage.domain[0], storage.domain[1])?;
            let _ = clear_owned_region(&mut storage.domain);
            Ok(())
        })
    }
    pub(super) fn public(
        &mut self,
        output: &mut [u8],
        authority: Sha3PublicDeclassification,
    ) -> Result<(), Error> {
        self.run(|storage| {
            storage
                .inner
                .engine
                .read_public(output, &mut storage.inner.stage.0, authority)
        })
    }
    pub(super) fn public_with_scratch(
        &mut self,
        output: &mut [u8],
        scratch: &mut [u8],
        authority: Sha3PublicDeclassification,
    ) -> Result<(), Error> {
        self.run(|storage| storage.inner.engine.read_public(output, scratch, authority))
    }
    pub(super) fn secret<'out>(
        &mut self,
        output: &'out mut [u8],
        final_bits: Option<u8>,
    ) -> Result<HardenedSha3SecretOutput<'out>, Error> {
        let length = output.len();
        // Own the entire destination before checking shape, terminal state or authority.
        let mut initialization = match begin_secret(output) {
            Ok(value) => value,
            Err(error) => {
                self.storage.clear();
                return Err(Error::from(error));
            }
        };
        self.run(|storage| {
            if let Some(valid) = final_bits
                && ((length == 0 && valid != 0) || (length != 0 && !(1..=8).contains(&valid)))
            {
                return Err(Error::OutputLength);
            }
            storage.inner.engine.preflight(length)?;
            let mut remaining = length;
            while remaining != 0 {
                let count = remaining.min(storage.inner.stage.0.len());
                let buffer = storage
                    .inner
                    .stage
                    .0
                    .get_mut(..count)
                    .ok_or(Error::OutputLength)?;
                storage.inner.engine.read(buffer)?;
                if remaining == count
                    && let Some(valid) = final_bits
                {
                    let last = buffer.last_mut().ok_or(Error::OutputLength)?;
                    brynja_core::apply_secret_byte_mask(
                        last,
                        u8::MAX >> 8_u8.saturating_sub(valid),
                        0,
                    );
                }
                initialization
                    .as_mut()
                    .ok_or(Error::SecretMemory)?
                    .write(buffer)
                    .map_err(|_| Error::SecretMemory)?;
                let _ = clear_owned_region(&mut storage.inner.stage.0);
                remaining = remaining.checked_sub(count).ok_or(Error::LengthOverflow)?;
            }
            finish_secret(initialization).map_err(Error::from)
        })
    }
}
