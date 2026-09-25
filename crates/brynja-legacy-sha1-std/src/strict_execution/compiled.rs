use super::{Cancellation, Digest, Error, Limits, OutputGuard, Session};
use brynja_legacy_sha1::Sha1Backend;
#[cfg(test)]
mod tests;
mod worker;

/// Protected legacy SHA-1 requiring the compiled SHA-NI or Arm SHA-1 kernel.
///
/// SHA-1 remains collision-broken and is not authentication. Requires the
/// default-off `strict-acceleration` feature and the full build-wide CPU bundle
/// (x86 SHA/SSE2 or Arm NEON/SHA2), on supported GNU/Linux native targets only.
/// Deployment must preserve the bundle for every worker throughout execution;
/// static admission is not runtime detection, affinity or a migration monitor.
/// Every request constructs and consumes its authority and scoped state on the
/// protected stack. No secret thread result, authority export, reset or fallback.
/// Ordinary input rejection/cancellation permits reuse; backend/invariant failure,
/// resource failure after arming and recoverable worker unwind quarantine.
/// Compiler/platform qualification and retest are pending. Caller input, abort,
/// privileged snapshots and arbitrary register interruptions remain excluded.
///
/// ```compile_fail
/// fn bound<T: Send>() {} bound::<brynja_legacy_sha1_std::strict_execution::CompiledSession>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {} bound::<brynja_legacy_sha1_std::strict_execution::CompiledSession>();
/// ```
/// ```compile_fail
/// fn bound<T: Copy>() {} bound::<brynja_legacy_sha1_std::strict_execution::CompiledSession>();
/// ```
/// ```compile_fail
/// fn bound<T: Clone>() {} bound::<brynja_legacy_sha1_std::strict_execution::CompiledSession>();
/// ```
/// ```compile_fail
/// fn bound<T: core::fmt::Debug>() {} bound::<brynja_legacy_sha1_std::strict_execution::CompiledSession>();
/// ```
/// ```compile_fail
/// use brynja_legacy_sha1_std::strict_execution::{CompiledSession, Digest, Error};
/// fn escape(s: &mut CompiledSession) -> Result<Digest<'static>, Error> { s.hash(b"") }
/// ```
/// ```compile_fail
/// use brynja_legacy_sha1_std::strict_execution::{CompiledSession, Error};
/// fn overlap(s: &mut CompiledSession) -> Result<(), Error> {
///     let output = s.hash(b"")?; s.quarantine(); let _ = output.expose(); Ok(())
/// }
/// ```
/// ```no_run
/// use brynja_legacy_sha1_std::strict_execution::{CompiledSession, Error, Limits};
/// fn compatibility_only(input: &[u8], limits: Limits) -> Result<(), Error> {
///     // Establish matching compiled CPU features and protected Linux resources first.
///     let mut session = CompiledSession::new(limits)?;
///     let output = session.hash(input)?;
///     assert_eq!(output.expose().len(), 20);
///     Ok(())
/// }
/// ```
pub struct CompiledSession {
    inner: Session,
    backend: Sha1Backend,
    quarantined: bool,
    #[cfg(test)]
    fault: tests::Fault,
}
impl CompiledSession {
    /// Preacquires resources and performs the required startup KAT on the protected stack.
    pub fn new(limits: Limits) -> Result<Self, Error> {
        super::require_target()?;
        let mut inner = Session::new(limits)?;
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
    /// Exact required backend, not independent verification or live CPU detection.
    pub const fn backend(&self) -> Sha1Backend {
        self.backend
    }
    /// Irreversible wrapper-local health.
    pub const fn is_quarantined(&self) -> bool {
        self.quarantined
    }
    /// Clears forgotten output and rejects all subsequent requests.
    pub fn quarantine(&mut self) {
        self.quarantined = true;
        self.inner.output.clear();
    }
    /// Complete byte input; all processing is on the protected worker.
    pub fn hash(&mut self, input: &[u8]) -> Result<Digest<'_>, Error> {
        self.hash_chunks(&[input], &[], 0, &Cancellation::new())
    }
    /// Byte chunks plus canonical MSB-first tail, with the scalar session's
    /// public bounds and 4096-byte cancellation intervals. Content validation
    /// occurs only on the protected worker. Errors clear output before returning.
    pub fn hash_chunks(
        &mut self,
        chunks: &[&[u8]],
        tail: &[u8],
        valid_bits: u8,
        cancel: &Cancellation,
    ) -> Result<Digest<'_>, Error> {
        self.inner.output.clear();
        if self.quarantined {
            return Err(Error::Quarantined);
        }
        super::validate_request(self.inner.limits, chunks, tail.len(), valid_bits)?;
        cancel.check()?;
        let mut guard = OutputGuard {
            output: &mut self.inner.output,
            complete: false,
        };
        self.quarantined = true;
        let request = worker::Request {
            backend: self.backend,
            chunks,
            tail,
            valid_bits,
            cancel,
            #[cfg(test)]
            fault: self.fault,
        };
        let destination = guard.output.as_bytes_mut();
        let mut result = Err(Error::Invariant);
        self.inner
            .stack
            .run(|| result = worker::run(request, destination))?;
        if matches!(result, Ok(()) | Err(Error::Cancelled | Error::InvalidBits)) {
            self.quarantined = false;
        }
        result?;
        cancel.check()?;
        guard.complete = true;
        drop(guard);
        Ok(Digest {
            output: &mut self.inner.output,
        })
    }
}
