use super::{
    Bits, Buffers, Cancellation, Error, LegacyUse, Limits, Output, Request, Session, Sha1,
    TagPolicy, types,
};
use brynja_crypto_cpu_std::macos_resident;
pub use brynja_legacy_hmac::execution::Sha1Backend;
use core::marker::PhantomData;
#[cfg(test)]
mod tests;
mod worker;

/// Explicit SHA-1 hardware execution with resident resources; never fallback.
///
/// Requires a native supported Apple Silicon macOS host and the complete build-wide SHA-1
/// target-feature bundle. Establish CPU/OS support for the entire deployment
/// before construction. Static selection is not runtime detection, a scheduler
/// lock or a VM-migration guarantee. Construction probes the backend on the
/// resident worker before accepting keys; each request reconstructs that exact
/// authority and all HMAC state on the worker, never on the caller's stack.
///
/// Backend, invariant and worker-unwind failures permanently quarantine the
/// session. Pre-entry thread-setup failure, malformed requests, cancellation and
/// tag mismatch preserve reuse, without authorizing fallback. Scalar [`Session`]
/// remains scalar under feature unification. Caller copies, registers, OS/TLS
/// diagnostic storage, interruption and fatal abort remain outside the owned
/// memory guarantee; this profile does not provide core-dump exclusion. Independent review and compiler/native qualification pending.
///
/// ```compile_fail
/// fn bound<T: Send>() {}
/// bound::<brynja_legacy_hmac_std::macos_resident::Sha1CompiledSession>();
/// ```
/// ```compile_fail
/// use brynja_legacy_hmac_std::macos_resident::{Sha1CompiledSession, Sha1, Output, Error};
/// fn escape(s: &mut Sha1CompiledSession) -> Result<Output<'static, Sha1>, Error> {
///     s.authenticate(b"key", b"message")
/// }
pub struct Sha1CompiledSession {
    inner: Session<Sha1>,
    backend: Sha1Backend,
    quarantined: bool,
    #[cfg(test)]
    fault: tests::Fault,
}
impl Sha1CompiledSession {
    /// Acquires all protections and probes the required compiled backend before
    /// accepting keys. Missing features/protections are errors, never portable.
    pub fn new(ack: LegacyUse, policy: TagPolicy, limits: Limits) -> Result<Self, Error> {
        let mut inner = Session::<Sha1>::new(ack, policy, limits)?;
        let mut result = Err(Error::Invariant);
        inner.stack.run(|| result = worker::probe())?;
        let backend = result?;
        Ok(Self {
            inner,
            backend,
            quarantined: false,
            #[cfg(test)]
            fault: tests::Fault::None,
        })
    }
    /// Non-authorizing route metadata, not native qualification.
    pub const fn backend(&self) -> Sha1Backend {
        self.backend
    }
    /// Public preselected width, not private accumulated length.
    pub const fn tag_bytes(&self) -> usize {
        self.inner.bytes
    }
    /// Wrapper-local terminal health, not a process-wide revocation service.
    pub const fn is_quarantined(&self) -> bool {
        self.quarantined
    }
    /// Permanently disables execution and clears any forgotten output loan.
    pub fn quarantine(&mut self) {
        self.quarantined = true;
        self.inner.output.clear();
        self.inner.staging.clear();
    }
    /// Complete byte request; all caller input buffers remain caller-owned.
    pub fn authenticate(&mut self, key: &[u8], message: &[u8]) -> Result<Output<'_, Sha1>, Error> {
        self.compute(
            Request {
                key,
                chunks: &[message],
                tail: Bits::empty(),
            },
            &Cancellation::new(),
        )
    }
    /// Same bounds and cancellation granularity as [`Session::compute`].
    pub fn compute(
        &mut self,
        request: Request<'_>,
        cancel: &Cancellation,
    ) -> Result<Output<'_, Sha1>, Error> {
        self.execute(request, None, cancel)?;
        Ok(Output {
            storage: &mut self.inner.output,
            identity: PhantomData,
        })
    }
    /// Compares the selected tag on the worker and releases only the decision.
    pub fn verify(
        &mut self,
        request: Request<'_>,
        candidate: &[u8],
        cancel: &Cancellation,
    ) -> Result<bool, Error> {
        self.execute(request, Some(candidate), cancel)?
            .ok_or(Error::Invariant)
    }
    fn execute(
        &mut self,
        request: Request<'_>,
        candidate: Option<&[u8]>,
        cancel: &Cancellation,
    ) -> Result<Option<bool>, Error> {
        self.inner.output.clear();
        self.inner.staging.clear();
        if self.quarantined {
            return Err(Error::Quarantined);
        }
        let mut guard = Buffers {
            output: &mut self.inner.output,
            staging: &mut self.inner.staging,
            keep: false,
        };
        types::validate(self.inner.limits, &request, candidate, self.inner.bytes)?;
        cancel.check()?;
        let verifying = candidate.is_some();
        // Arm before launching: unwinding or a malformed worker result cannot
        // accidentally rehabilitate an authority or retain caller-visible output.
        self.quarantined = true;
        let backend = self.backend;
        let bytes = self.inner.bytes;
        let staging = guard.staging.as_bytes_mut();
        let output = guard.output.as_bytes_mut();
        #[cfg(test)]
        let fault = (self.inner.fault, self.fault);
        let mut result = Err(Error::Invariant);
        let launch = self.inner.stack.run(|| {
            #[cfg(test)]
            {
                super::tests::configure(fault.0);
                tests::configure(fault.1);
            }
            result = worker::run(backend, bytes, request, candidate, cancel, staging, output);
            #[cfg(test)]
            tests::result(&mut result);
        });
        if let Err(error) = launch {
            if pre_entry(error) {
                self.quarantined = false;
            }
            return Err(error.into());
        }
        match result {
            Ok(value) => {
                if value.is_some() != verifying {
                    return Err(Error::Invariant);
                }
                self.quarantined = false;
                cancel.check()?;
                guard.keep = !verifying;
                Ok(value)
            }
            Err(
                error @ (Error::Cancelled
                | Error::InvalidBits
                | Error::Mac(brynja_legacy_hmac::Error::MessageTooLong)),
            ) => {
                self.quarantined = false;
                Err(error)
            }
            Err(error) => Err(error),
        }
    }
}

fn pre_entry(error: macos_resident::Error) -> bool {
    // Both are returned before pthread_create succeeds. A join failure aborts;
    // worker panic/protocol failures must never be mistaken for non-entry.
    matches!(
        error,
        macos_resident::Error::ThreadStart | macos_resident::Error::ThreadAttributes
    )
}
