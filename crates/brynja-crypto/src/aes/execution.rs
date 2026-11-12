//! Explicit accelerated AES owners, never selected by portable constructors.
//!
//! Enable `aes-static-execution` and compile for the complete target ISA, or
//! enable `aes-runtime-execution` and borrow an admitted authority from the
//! separate `brynja_crypto_cpu_std::aes` adapter. Static binaries must run only
//! on compatible CPUs for their entire lifetime. Neither feature is a message
//! mode, authentication, speed guarantee or physical-fault qualification.
//!
//! Expansion and rounds use the selected hardware kernels. Keys, schedules and
//! staging use clearing owners. No claim covers compiler copies, registers
//! outside the kernel boundary, spills, forgotten owners, aborts or dumps.
//! Failed selected operations quarantine the shared authority without fallback.

use super::{
    OwnedSecretRegion, PhantomData, PublicCiphertext, Scratch, SecretBlock,
    SecretRegionInitialization,
};
use brynja_crypto_cpu::aes::Session;
pub use brynja_crypto_cpu::aes::{Authority, DitPolicy, Health, Kernel, Report};

/// Value-free storage or execution failure. Neither requests a portable retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// A secret-storage or fixed-size invariant failed.
    SecretMemory,
    /// The selected authority rejected execution.
    Execution(brynja_crypto_cpu::aes::Error),
}
impl From<super::Error> for Error {
    fn from(_: super::Error) -> Self {
        Self::SecretMemory
    }
}
impl From<brynja_core::SecretMemoryError> for Error {
    fn from(_: brynja_core::SecretMemoryError) -> Self {
        Self::SecretMemory
    }
}
impl From<brynja_crypto_cpu::aes::Error> for Error {
    fn from(error: brynja_crypto_cpu::aes::Error) -> Self {
        Self::Execution(error)
    }
}

struct Operation<'a, 'owner> {
    session: &'a Session<'owner>,
    completed: bool,
}
impl Drop for Operation<'_, '_> {
    fn drop(&mut self) {
        if !self.completed {
            self.session.quarantine();
        }
    }
}

macro_rules! owner {
    ($name:ident, $k:literal, $s:literal, $storage:literal, $cached:literal, $expand:ident, $encrypt:ident, $decrypt:ident) => {
        /// Explicit hardware-round key owner with clearing caller storage.
        ///
        /// Borrows one authority for its lifetime. No Copy, Clone, Debug, Send,
        /// Sync, schedule export or route replacement. The `ExpandedKey` form
        /// retains a forward schedule; the `Key` form expands per operation.
        #[must_use = "keep the clearing key owner live until use is complete"]
        pub struct $name<'storage, 'authority> {
            region: OwnedSecretRegion<'storage>,
            session: Session<'authority>,
        }

        impl<'storage, 'authority> $name<'storage, 'authority> {
            /// Admits clearing storage and binds to an already-tested authority.
            /// Rejection/error/unwind clears the admitted storage. Input copies
            /// remain the caller's responsibility. Cached expansion errors also
            /// revoke the selected authority; no portable retry is performed.
            pub fn new(
                authority: &'authority Authority,
                input: &[u8; $k],
                storage: &'storage mut [u8; $storage],
            ) -> Result<Self, Error> {
                let mut destination = SecretRegionInitialization::begin(storage)?;
                let session = authority.session()?;
                let mut guard = Operation {
                    session: &session,
                    completed: false,
                };
                if $cached {
                    let mut schedule = Scratch::<$s>::new();
                    Self::expand(&session, input, &mut schedule.0)?;
                    destination.write(&schedule.0)?;
                } else {
                    destination.write(input)?;
                }
                let region = destination.finish()?;
                guard.completed = true;
                drop(guard);
                Ok(Self { region, session })
            }

            /// Clears the complete key or cached schedule and consumes the owner.
            pub fn clear(self) {
                let _ = self.region.clear();
            }

            /// Observes current authority health; cannot authorize or renew work.
            pub fn report(&self) -> Report {
                self.session.report()
            }

            fn expand(
                session: &Session<'_>,
                input: &[u8],
                output: &mut [u8; $s],
            ) -> Result<(), Error> {
                let key = input.try_into().map_err(|_| Error::SecretMemory)?;
                // Test hooks surround the opaque, non-unwinding assembly, not
                // its individual instructions. Outer guards own all cleanup.
                #[cfg(test)]
                super::tests::execution_expansion_checkpoint(session)?;
                session.$expand(key, output)?;
                #[cfg(test)]
                super::tests::execution_expansion_checkpoint(session)?;
                session.check()?;
                Ok(())
            }

            fn with_schedule<T>(
                &self,
                operation: impl FnOnce(&[u8; $s]) -> Result<T, Error>,
            ) -> Result<T, Error> {
                self.session.check()?;
                let mut guard = Operation {
                    session: &self.session,
                    completed: false,
                };
                let result = if $cached {
                    let schedule = self
                        .region
                        .expose()
                        .try_into()
                        .map_err(|_| Error::SecretMemory)?;
                    operation(schedule)?
                } else {
                    let mut schedule = Scratch::<$s>::new();
                    Self::expand(&self.session, self.region.expose(), &mut schedule.0)?;
                    operation(&schedule.0)?
                };
                guard.completed = true;
                Ok(result)
            }

            /// Encrypts one block into clearing storage. Rejection, including
            /// quarantine, clears the complete admitted destination.
            pub fn encrypt_block<'out>(
                &self,
                input: &[u8; 16],
                output: &'out mut [u8; 16],
            ) -> Result<SecretBlock<'out>, Error> {
                self.secret(input, output, false)
            }

            /// Decrypts one block into a clearing owner. No authentication.
            /// Errors/unwinds clear the destination; no public decrypt exists.
            pub fn decrypt_block<'out>(
                &self,
                input: &[u8; 16],
                output: &'out mut [u8; 16],
            ) -> Result<SecretBlock<'out>, Error> {
                self.secret(input, output, true)
            }

            fn secret<'out>(
                &self,
                input: &[u8; 16],
                output: &'out mut [u8; 16],
                inverse: bool,
            ) -> Result<SecretBlock<'out>, Error> {
                let mut destination = SecretRegionInitialization::begin(output)?;
                self.with_schedule(|schedule| {
                    let mut state = Scratch::<16>::new();
                    state.0.copy_from_slice(input);
                    if inverse {
                        self.session.$decrypt(&mut state.0, schedule)?;
                    } else {
                        self.session.$encrypt(&mut state.0, schedule)?;
                    }
                    destination.write(&state.0)?;
                    Ok(SecretBlock {
                        region: destination.finish()?,
                        local: PhantomData,
                    })
                })
            }

            /// Explicit public encryption. Caller output changes only after a
            /// successful operation; errors/unwinds preserve it byte-for-byte.
            pub fn encrypt_block_public(
                &self,
                input: &[u8; 16],
                output: &mut [u8; 16],
                _release: PublicCiphertext,
            ) -> Result<(), Error> {
                self.with_schedule(|schedule| {
                    let mut state = Scratch::<16>::new();
                    state.0.copy_from_slice(input);
                    self.session.$encrypt(&mut state.0, schedule)?;
                    output.copy_from_slice(&state.0);
                    Ok(())
                })
            }
        }
    };
}

owner!(
    Aes128Key, 16, 176, 16, false, expand128, encrypt128, decrypt128
);
owner!(
    Aes128ExpandedKey,
    16,
    176,
    176,
    true,
    expand128,
    encrypt128,
    decrypt128
);
owner!(
    Aes192Key, 24, 208, 24, false, expand192, encrypt192, decrypt192
);
owner!(
    Aes192ExpandedKey,
    24,
    208,
    208,
    true,
    expand192,
    encrypt192,
    decrypt192
);
owner!(
    Aes256Key, 32, 240, 32, false, expand256, encrypt256, decrypt256
);
owner!(
    Aes256ExpandedKey,
    32,
    240,
    240,
    true,
    expand256,
    encrypt256,
    decrypt256
);
