use super::{Cleanup, HardenedSha2Owner, PhantomData, PublicDeclassification, initialize64};
use crate::{BitString, Sha512TBits, Sha512TDigest, Sha512TError, Sha512TSecretDigest};
use brynja_core::SecretRegionInitialization;

/// Caller-owned scoped storage for one validated general SHA-512/t identity.
///
/// The parameter is public and fixed for the lifetime of this workspace.
/// Each computation derives its public IV before loading secret input. Active
/// storage is borrowed, never moved into finalization; scope exit clears it
/// even if the handle is forgotten. Registers, compiler copies/spills, caller
/// input and aborts are outside this owned-storage guarantee.
///
/// ```
/// use brynja_hash_sha2::{Sha512TBits, hardened_in_place::Sha512TWorkspace};
/// let parameter = Sha512TBits::new(9)?;
/// let mut workspace = Sha512TWorkspace::new(parameter);
/// let mut output = [0u8; 2];
/// let secret = workspace.with(|mut state| {
///     state.update(b"abc")?;
///     state.finalize_secret(&mut output)
/// })?;
/// assert_eq!(secret.parameter(), parameter);
/// assert_eq!(secret.as_bytes()[1] & 0x7f, 0);
/// drop(secret);
/// assert_eq!(output, [0; 2]);
/// # Ok::<(), brynja_hash_sha2::Sha512TError>(())
/// ```
/// ```compile_fail
/// use brynja_hash_sha2::{Sha512TBits, hardened_in_place::Sha512TWorkspace};
/// let mut w = Sha512TWorkspace::new(Sha512TBits::new(9)?);
/// let escaped = w.with(|state| state);
/// # Ok::<(), brynja_hash_sha2::Sha512TError>(())
/// ```
/// ```compile_fail
/// use brynja_hash_sha2::{Sha512TBits, hardened_in_place::Sha512TWorkspace};
/// let mut w = Sha512TWorkspace::new(Sha512TBits::new(9)?);
/// w.with(|_state| w.with(|_other| ()));
/// # Ok::<(), brynja_hash_sha2::Sha512TError>(())
/// ```
/// ```compile_fail
/// fn bound<T: Copy>() {}
/// bound::<brynja_hash_sha2::hardened_in_place::Sha512TWorkspace>();
/// ```
/// ```compile_fail
/// fn bound<T: Clone>() {}
/// bound::<brynja_hash_sha2::hardened_in_place::Sha512TWorkspace>();
/// ```
/// ```compile_fail
/// fn bound<T: core::fmt::Debug>() {}
/// bound::<brynja_hash_sha2::hardened_in_place::Sha512TWorkspace>();
/// ```
/// ```compile_fail
/// fn bound<T: Send>() {}
/// bound::<brynja_hash_sha2::hardened_in_place::Sha512TWorkspace>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {}
/// bound::<brynja_hash_sha2::hardened_in_place::Sha512TWorkspace>();
/// ```
pub struct Sha512TWorkspace {
    owner: HardenedSha2Owner,
    parameter: Sha512TBits,
    thread_bound: PhantomData<*mut ()>,
}

impl Sha512TWorkspace {
    /// Creates secret-free fixed storage; IV derivation occurs within `with`.
    #[must_use]
    pub fn new(parameter: Sha512TBits) -> Self {
        Self {
            owner: HardenedSha2Owner::new64([0; 8]),
            parameter,
            thread_bound: PhantomData,
        }
    }

    /// The exact public identity, not merely its rounded output byte width.
    #[must_use]
    pub const fn parameter(&self) -> Sha512TBits {
        self.parameter
    }

    /// Runs a scoped computation without moving the active secret owner.
    /// The handle cannot escape; a separately borrowed secret digest can.
    pub fn with<R>(&mut self, operation: impl for<'state> FnOnce(Sha512T<'state>) -> R) -> R {
        self.owner.wipe();
        initialize64(&mut self.owner, self.parameter.initial_words());
        let cleanup = Cleanup {
            owner: &mut self.owner,
            keep: false,
        };
        operation(Sha512T {
            owner: &mut *cleanup.owner,
            parameter: self.parameter,
            active: true,
            thread_bound: PhantomData,
        })
    }
}

/// Exclusive scoped SHA-512/t handle with parameter-bound secret output.
///
/// Errors clear and terminate this state. No public accumulated-length or
/// preflight-length query is available. Partial input/output is MSB-first.
/// ```compile_fail
/// fn bound<T: Copy>() {}
/// bound::<brynja_hash_sha2::hardened_in_place::Sha512T<'static>>();
/// ```
/// A secret result cannot implicitly become the copyable public digest:
/// ```compile_fail
/// use brynja_hash_sha2::{Sha512TBits, Sha512TDigest, hardened_in_place::Sha512TWorkspace};
/// let mut w = Sha512TWorkspace::new(Sha512TBits::new(9)?);
/// let mut output = [0; 2];
/// let public: Sha512TDigest = w.with(|state| state.finalize_secret(&mut output))?;
/// # Ok::<(), brynja_hash_sha2::Sha512TError>(())
/// ```
/// ```compile_fail
/// fn bound<T: Clone>() {}
/// bound::<brynja_hash_sha2::hardened_in_place::Sha512T<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: core::fmt::Debug>() {}
/// bound::<brynja_hash_sha2::hardened_in_place::Sha512T<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Send>() {}
/// bound::<brynja_hash_sha2::hardened_in_place::Sha512T<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {}
/// bound::<brynja_hash_sha2::hardened_in_place::Sha512T<'static>>();
/// ```
#[must_use = "finalize or cancel the scoped state"]
pub struct Sha512T<'state> {
    owner: &'state mut HardenedSha2Owner,
    parameter: Sha512TBits,
    active: bool,
    thread_bound: PhantomData<*mut ()>,
}

impl Sha512T<'_> {
    /// Exact public parameter; no secret metadata is exposed.
    #[must_use]
    pub const fn parameter(&self) -> Sha512TBits {
        self.parameter
    }

    /// Absorbs bytes; error or recoverable unwind clears and disables the state.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Sha512TError> {
        self.check()?;
        self.active = false;
        let mut cleanup = Cleanup {
            owner: &mut *self.owner,
            keep: false,
        };
        let result = cleanup
            .owner
            .update64(input)
            .map_err(|()| Sha512TError::MessageTooLong);
        if result.is_ok() {
            cleanup.keep = true;
            self.active = true;
        }
        result
    }

    /// Consumes the handle and transfers an exact-width, parameter-bound secret
    /// destination owner. Every error clears the complete destination.
    pub fn finalize_secret(
        self,
        destination: &mut [u8],
    ) -> Result<Sha512TSecretDigest<'_>, Sha512TError> {
        self.secret(None, destination)
    }

    /// Includes one final canonical bit string before typed secret output.
    pub fn finalize_bits_secret<'out>(
        self,
        input: BitString<'_>,
        destination: &'out mut [u8],
    ) -> Result<Sha512TSecretDigest<'out>, Sha512TError> {
        self.secret(Some(input), destination)
    }

    /// Consumes the handle and deliberately returns a copyable public digest.
    pub fn finalize_public(
        self,
        authority: PublicDeclassification,
    ) -> Result<Sha512TDigest, Sha512TError> {
        self.public(None, authority)
    }

    /// Includes final canonical bits before deliberate public declassification.
    pub fn finalize_bits_public(
        self,
        input: BitString<'_>,
        authority: PublicDeclassification,
    ) -> Result<Sha512TDigest, Sha512TError> {
        self.public(Some(input), authority)
    }

    /// Clears the borrowed owner without producing output.
    pub fn cancel(self) {}

    fn check(&self) -> Result<(), Sha512TError> {
        if self.active {
            Ok(())
        } else {
            Err(Sha512TError::StateConsumed)
        }
    }

    fn stage(&mut self, input: Option<BitString<'_>>) -> Result<(), Sha512TError> {
        self.check()?;
        let (partial, bits) = if let Some(input) = input {
            let bits = crate::hardened::finalize_bits_length64(self.owner, input)
                .map_err(|()| Sha512TError::MessageTooLong)?;
            let (complete, partial) = input.split();
            self.update(complete)?;
            (partial, bits)
        } else {
            (
                None,
                self.owner
                    .message_bytes64()
                    .checked_mul(8)
                    .ok_or(Sha512TError::MessageTooLong)?,
            )
        };
        let width = self.parameter.output_bytes();
        self.owner.finalize64(partial, bits, width);
        let last = width.checked_sub(1).ok_or(Sha512TError::OutputLength)?;
        *self
            .owner
            .output_staging
            .get_mut(last)
            .ok_or(Sha512TError::OutputLength)? &= self.parameter.last_byte_mask();
        self.active = false;
        Ok(())
    }

    fn secret<'out>(
        mut self,
        input: Option<BitString<'_>>,
        destination: &'out mut [u8],
    ) -> Result<Sha512TSecretDigest<'out>, Sha512TError> {
        let width = destination.len();
        if width == 0 {
            return Err(Sha512TError::OutputLength);
        }
        // Establish clearing before any fallible state/length processing.
        let mut guard = SecretRegionInitialization::begin(destination)?;
        if width != self.parameter.output_bytes() {
            return Err(Sha512TError::OutputLength);
        }
        self.stage(input)?;
        guard.write(self.owner.staged(width).ok_or(Sha512TError::OutputLength)?)?;
        Ok(Sha512TSecretDigest::from_region(
            self.parameter,
            guard.finish()?,
        ))
    }

    fn public(
        mut self,
        input: Option<BitString<'_>>,
        _authority: PublicDeclassification,
    ) -> Result<Sha512TDigest, Sha512TError> {
        self.stage(input)?;
        Sha512TDigest::computed(self.parameter, &self.owner.output_staging)
    }
}

impl Drop for Sha512T<'_> {
    fn drop(&mut self) {
        self.owner.wipe();
    }
}

#[cfg(test)]
mod tests;
