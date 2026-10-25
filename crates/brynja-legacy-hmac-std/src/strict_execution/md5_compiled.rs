use super::{
    Bits, Buffers, Cancellation, Error, LegacyUse, Md5, PublicDeclassification, TagPolicy,
};
use brynja_crypto_cpu_std::protected_memory::{self, ProtectedBytes, ProtectedStack};
pub use brynja_legacy_hmac::md5_batch::Md5Backend;
#[cfg(test)]
mod tests;
mod types;
mod worker;
pub use types::{Md5BatchInput, Md5BatchLimits, Md5BatchOutput};

/// Explicit HMAC-MD5 SIMD on a protected worker; never an ordinary-memory fallback.
///
/// Requires native supported GNU/Linux and deployment-wide AVX2/OS YMM support
/// or little-endian AArch64 NEON. Build features are not runtime detection,
/// scheduler locking or a VM-migration guarantee. Establish those guarantees
/// before construction. All authority, key normalization, ipad/opad and tag
/// computation live on the joined worker; no host-created keyed owner is moved.
///
/// At least one aligned full group is required: slots 0..8 for AVX2, or 0..4
/// or 4..8 for NEON. Inactive slots are not dummy work. Ineligible shapes reject.
/// Unequal suffixes/padding and ineligible long-key normalization use the leaf's
/// preselected hardened scalar route, never error-driven fallback. Slot activity,
/// lengths and compression budgets are PUBLIC; pad externally if confidential.
///
/// Caller inputs/copies, registers, OS/TLS diagnostic storage, interruption and
/// fatal abort remain outside the owned-memory contract. Independent review and
/// compiler/native qualification are pending. MD5 is legacy-only, not FIPS.
///
/// ```compile_fail
/// fn bound<T: Send>() {}
/// bound::<brynja_legacy_hmac_std::strict_execution::Md5BatchSession>();
/// ```
/// Requiring SIMD applies to ipad/opad passes, not every key compression.
/// Sparse long keys are normalized by a separate hardened portable batch before
/// those passes; this is public-shape selection, never fallback after failure.
pub struct Md5BatchSession {
    stack: ProtectedStack,
    staging: ProtectedBytes,
    output: ProtectedBytes,
    backend: Md5Backend,
    bytes: usize,
    limits: Md5BatchLimits,
    quarantined: bool,
    #[cfg(test)]
    fault: tests::Fault,
}
impl Md5BatchSession {
    /// Acquires every resource and probes the required SIMD authority on the
    /// worker before accepting keys. Unsupported platforms/features return errors.
    pub fn new(_ack: LegacyUse, policy: TagPolicy, limits: Md5BatchLimits) -> Result<Self, Error> {
        let bytes = policy.bytes::<Md5>()?;
        let mut stack = ProtectedStack::new(limits.stack_bytes, limits.max_stack_mapping_bytes)?;
        let staging = ProtectedBytes::new(128, limits.max_buffer_mapping_bytes)?;
        let output = ProtectedBytes::new(128, limits.max_buffer_mapping_bytes)?;
        let mut result = Err(Error::Invariant);
        stack.run(|| result = worker::probe())?;
        Ok(Self {
            stack,
            staging,
            output,
            backend: result?,
            bytes,
            limits,
            quarantined: false,
            #[cfg(test)]
            fault: tests::Fault::None,
        })
    }
    /// Non-authorizing selected identity, not independent qualification.
    pub const fn backend(&self) -> Md5Backend {
        self.backend
    }
    /// Required aligned independent-message group width.
    pub const fn vector_width(&self) -> usize {
        self.backend.lane_width()
    }
    /// Public, preselected tag width.
    pub const fn tag_bytes(&self) -> usize {
        self.bytes
    }
    /// Wrapper-local terminal health.
    pub const fn is_quarantined(&self) -> bool {
        self.quarantined
    }
    /// Permanently disables execution and clears even forgotten output loans.
    pub fn quarantine(&mut self) {
        self.quarantined = true;
        self.output.clear();
        self.staging.clear();
    }
    /// Computes all active lanes using one shared per-request compression budget.
    /// Only borrowed secret output is released. Cancellation may race completion.
    pub fn compute(
        &mut self,
        inputs: &[Option<Md5BatchInput<'_>>; 8],
        cancel: &Cancellation,
    ) -> Result<Md5BatchOutput<'_>, Error> {
        self.execute(inputs, None, cancel)?;
        Ok(Md5BatchOutput {
            storage: &mut self.output,
            active: inputs.each_ref().map(Option::is_some),
            bytes: self.bytes,
        })
    }
    /// Checks every active candidate without mismatch-dependent early exit.
    /// Candidate presence/width must exactly match the input slots and tag policy.
    /// Releases only the aggregate decision, never per-lane match information.
    /// `Ok(())` means every tag matched; otherwise authentication fails. A
    /// mismatch returns [`crate::VerificationError::Mismatch`].
    pub fn verify(
        &mut self,
        inputs: &[Option<Md5BatchInput<'_>>; 8],
        candidates: &[Option<&[u8]>; 8],
        cancel: &Cancellation,
    ) -> Result<(), crate::VerificationError<Error>> {
        crate::verification::finish(
            self.execute(inputs, Some(candidates), cancel)
                .map_err(crate::VerificationError::Operation)?,
            Error::Invariant,
        )
    }
    fn execute(
        &mut self,
        inputs: &[Option<Md5BatchInput<'_>>; 8],
        candidates: Option<&[Option<&[u8]>; 8]>,
        cancel: &Cancellation,
    ) -> Result<Option<bool>, Error> {
        self.output.clear();
        self.staging.clear();
        if self.quarantined {
            return Err(Error::Quarantined);
        }
        let mut guard = Buffers {
            output: &mut self.output,
            staging: &mut self.staging,
            keep: false,
        };
        types::validate(
            inputs,
            candidates,
            self.limits,
            self.backend.lane_width(),
            self.bytes,
        )?;
        cancel.check()?;
        self.quarantined = true;
        let parameters = worker::Parameters {
            backend: self.backend,
            bytes: self.bytes,
            budget: self.limits.max_compressions,
        };
        let staging = guard.staging.as_bytes_mut();
        let output = guard.output.as_bytes_mut();
        #[cfg(test)]
        let fault = self.fault;
        let mut result = Err(Error::Invariant);
        let launch = self.stack.run(|| {
            #[cfg(test)]
            tests::configure(fault);
            result = worker::run(parameters, inputs, candidates, cancel, staging, output);
            #[cfg(test)]
            tests::result(&mut result);
        });
        if let Err(error) = launch {
            // Both variants are returned before pthread_create succeeds.
            if matches!(
                error,
                protected_memory::Error::ThreadStart | protected_memory::Error::ThreadAttributes
            ) {
                self.quarantined = false;
            }
            return Err(error.into());
        }
        match result {
            Ok(value) => {
                if value.is_some() != candidates.is_some() {
                    return Err(Error::Invariant);
                }
                self.quarantined = false;
                cancel.check()?;
                guard.keep = candidates.is_none();
                Ok(value)
            }
            Err(error @ (Error::Cancelled | Error::InvalidBits)) => {
                self.quarantined = false;
                Err(error)
            }
            Err(Error::Mac(error)) if crate::common::recoverable_md5(error) => {
                self.quarantined = false;
                Err(Error::Mac(error))
            }
            Err(error) => Err(error),
        }
    }
}
