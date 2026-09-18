use super::{
    Cleanup, Engine, Error, Execution, HardenedSha2Owner, PublicDeclassification, Route, begin,
    initialize64,
};
use crate::{
    BitString, Sha512TBits, Sha512TDigest, Sha512TSecretDigest, execution::Output,
    hardened_execution::GeneralSecretOutput,
};
use brynja_core::SecretRegionInitialization;

/// Scoped general SHA-512/t engine and CPU scratch with a fixed public identity.
///
/// Requires `general-sha512-t` and `hardened-execution`. The route is explicitly
/// portable, static or hosted; authority cannot be replaced or revived. Secret
/// input is accepted only inside `with`, after borrowing final storage. Scope
/// exit clears the hash owner, including forgotten handles/recoverable unwind.
/// CPU scratch retains the existing per-operation cleanup. Registers, spills,
/// compiler-created copies, caller buffers and abort remain outside this claim.
///
/// ```
/// use brynja_hash_sha2::{Sha512TBits, hardened_execution::{Execution, in_place::Sha512TWorkspace}};
/// let parameter = Sha512TBits::new(9).unwrap();
/// let mut workspace = Sha512TWorkspace::new(parameter, Execution::portable())?;
/// let mut output = [0; 2];
/// let secret = workspace.with(|mut state| {
///     state.update(b"abc")?;
///     state.finalize_secret(&mut output)
/// })??;
/// assert_eq!(secret.digest.parameter(), parameter);
/// assert_eq!(secret.digest.as_bytes()[1] & 0x7f, 0);
/// assert_eq!(secret.report.portable_iv_blocks, 1);
/// drop(secret);
/// assert_eq!(output, [0; 2]);
/// # Ok::<(), brynja_hash_sha2::hardened_execution::Error>(())
/// ```
/// ```compile_fail
/// use brynja_hash_sha2::{Sha512TBits, hardened_execution::{Execution, in_place::Sha512TWorkspace}};
/// let mut w = Sha512TWorkspace::new(Sha512TBits::new(9).unwrap(), Execution::portable()).unwrap();
/// let escaped = w.with(|state| state);
/// ```
/// ```compile_fail
/// use brynja_hash_sha2::{Sha512TBits, hardened_execution::{Execution, in_place::Sha512TWorkspace}};
/// let mut w = Sha512TWorkspace::new(Sha512TBits::new(9).unwrap(), Execution::portable()).unwrap();
/// w.with(|_state| w.with(|_other| ()));
/// ```
/// ```compile_fail
/// fn bound<T: Copy>() {}
/// bound::<brynja_hash_sha2::hardened_execution::in_place::Sha512TWorkspace<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Clone>() {}
/// bound::<brynja_hash_sha2::hardened_execution::in_place::Sha512TWorkspace<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: core::fmt::Debug>() {}
/// bound::<brynja_hash_sha2::hardened_execution::in_place::Sha512TWorkspace<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Send>() {}
/// bound::<brynja_hash_sha2::hardened_execution::in_place::Sha512TWorkspace<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {}
/// bound::<brynja_hash_sha2::hardened_execution::in_place::Sha512TWorkspace<'static>>();
/// ```
/// ```compile_fail
/// use brynja_hash_sha2::{Sha512TBits, hardened_execution::{Execution, Kernel, in_place::Sha512TWorkspace}};
/// use brynja_crypto_cpu::static_execution::Authority;
/// let workspace = {
///     let owner = Authority::new(Kernel::ArmSha512).unwrap();
///     Sha512TWorkspace::new(Sha512TBits::new(9).unwrap(), Execution::from_static(&owner).unwrap()).unwrap()
/// };
/// drop(workspace);
/// ```
pub struct Sha512TWorkspace<'authority> {
    engine: Engine<'authority>,
    parameter: Sha512TBits,
}

impl<'authority> Sha512TWorkspace<'authority> {
    /// Binds a compatible wide route, before any secret input or IV derivation.
    pub fn new(parameter: Sha512TBits, execution: Execution<'authority>) -> Result<Self, Error> {
        Ok(Self {
            engine: Engine::new(HardenedSha2Owner::new64([0; 8]), execution, true, true)?,
            parameter,
        })
    }
    /// Exact public parameter, not merely rounded output width.
    #[must_use]
    pub const fn parameter(&self) -> Sha512TBits {
        self.parameter
    }
    /// Selected public execution route; not independent-verification evidence.
    #[must_use]
    pub const fn route(&self) -> Route {
        self.engine.report.route
    }
    /// Runs one computation without moving the active engine or CPU scratch.
    ///
    /// Rechecks the same authority, clears storage, and derives the public IV.
    /// The outer result is admission; the inner value is the callback result.
    /// Admission failure skips the callback and cannot clear captured buffers.
    /// Secret-output clearing starts when finalization receives a destination.
    pub fn with<R>(
        &mut self,
        operation: impl for<'scope> FnOnce(Sha512T<'scope, 'authority>) -> R,
    ) -> Result<R, Error> {
        self.engine.restart()?;
        initialize64(&mut self.engine, self.parameter.initial_words());
        let cleanup = Cleanup {
            engine: &mut self.engine,
            keep: false,
        };
        Ok(operation(Sha512T {
            engine: &mut *cleanup.engine,
            parameter: self.parameter,
        }))
    }
}

/// Exclusive general-t handle, with no public length/preflight query.
///
/// Every update failure clears and disables this computation. Finalization
/// consumes it. Final reports disclose public route/work metadata; they do not
/// provide a message-length confidentiality or traffic-analysis guarantee.
/// ```compile_fail
/// fn bound<T: Copy>() {}
/// bound::<brynja_hash_sha2::hardened_execution::in_place::Sha512T<'static, 'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Clone>() {}
/// bound::<brynja_hash_sha2::hardened_execution::in_place::Sha512T<'static, 'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: core::fmt::Debug>() {}
/// bound::<brynja_hash_sha2::hardened_execution::in_place::Sha512T<'static, 'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Send>() {}
/// bound::<brynja_hash_sha2::hardened_execution::in_place::Sha512T<'static, 'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {}
/// bound::<brynja_hash_sha2::hardened_execution::in_place::Sha512T<'static, 'static>>();
/// ```
/// ```compile_fail
/// use brynja_hash_sha2::{Sha512TDigest, Sha512TBits, hardened_execution::{Execution, in_place::Sha512TWorkspace}};
/// let mut w = Sha512TWorkspace::new(Sha512TBits::new(9).unwrap(), Execution::portable()).unwrap();
/// let mut output = [0; 2];
/// let secret = w.with(|state| state.finalize_secret(&mut output)).unwrap().unwrap();
/// let public: Sha512TDigest = secret.digest;
/// ```
#[must_use = "finalize or cancel the scoped state"]
pub struct Sha512T<'scope, 'authority> {
    engine: &'scope mut Engine<'authority>,
    parameter: Sha512TBits,
}

impl Sha512T<'_, '_> {
    /// Exact public identity; no accumulated secret-derived metadata is returned.
    #[must_use]
    pub const fn parameter(&self) -> Sha512TBits {
        self.parameter
    }
    /// Absorbs complete bytes; any failure/unwind clears and disables this state.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        let mut cleanup = Cleanup {
            engine: &mut *self.engine,
            keep: false,
        };
        let result = cleanup.engine.update(input);
        if result.is_ok() {
            cleanup.keep = true;
        }
        result
    }
    /// Consumes and clears without output.
    pub fn cancel(self) {}
    /// Parameter-bound secret output. Every error clears the full destination.
    pub fn finalize_secret(self, destination: &mut [u8]) -> Result<GeneralSecretOutput<'_>, Error> {
        let guard = begin(destination, self.parameter.output_bytes())?;
        self.secret(None, guard)
    }
    /// Includes final canonical MSB-first bits before typed secret output.
    pub fn finalize_bits_secret<'out>(
        self,
        input: BitString<'_>,
        destination: &'out mut [u8],
    ) -> Result<GeneralSecretOutput<'out>, Error> {
        let guard = begin(destination, self.parameter.output_bytes())?;
        self.secret(Some(input), guard)
    }
    /// Explicitly declassifies the parameter-bound digest into a public type.
    pub fn finalize_public(
        self,
        authority: PublicDeclassification,
    ) -> Result<Output<Sha512TDigest>, Error> {
        self.public(None, authority)
    }
    /// Includes final canonical bits before explicit public declassification.
    pub fn finalize_bits_public(
        self,
        input: BitString<'_>,
        authority: PublicDeclassification,
    ) -> Result<Output<Sha512TDigest>, Error> {
        self.public(Some(input), authority)
    }
    fn finish(&mut self, input: Option<BitString<'_>>) -> Result<(), Error> {
        self.engine.finish(
            input,
            self.parameter.output_bytes(),
            self.parameter.last_byte_mask(),
        )
    }
    fn secret<'out>(
        mut self,
        input: Option<BitString<'_>>,
        mut guard: SecretRegionInitialization<'out>,
    ) -> Result<GeneralSecretOutput<'out>, Error> {
        self.finish(input)?;
        guard.write(
            self.engine
                .owner
                .staged(self.parameter.output_bytes())
                .ok_or(Error::OutputLength)?,
        )?;
        Ok(GeneralSecretOutput {
            digest: Sha512TSecretDigest::from_region(self.parameter, guard.finish()?),
            report: self.engine.report,
        })
    }
    fn public(
        mut self,
        input: Option<BitString<'_>>,
        _authority: PublicDeclassification,
    ) -> Result<Output<Sha512TDigest>, Error> {
        self.finish(input)?;
        let digest = Sha512TDigest::computed(
            self.parameter,
            self.engine
                .owner
                .staged(self.parameter.output_bytes())
                .ok_or(Error::OutputLength)?,
        )
        .map_err(|_| Error::OutputLength)?;
        Ok(Output {
            digest,
            report: self.engine.report,
        })
    }
}

impl Drop for Sha512T<'_, '_> {
    fn drop(&mut self) {
        self.engine.invalidate();
    }
}

#[cfg(test)]
mod tests;
