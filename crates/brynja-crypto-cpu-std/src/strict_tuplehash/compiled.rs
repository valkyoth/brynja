use super::{Algorithm, Bits, Buffers, Cancellation, Error, Item, Limits, Output, Session};
pub use brynja_crypto_cpu::static_execution::Kernel;
#[cfg(test)]
mod tests;
mod worker;

/// Protected-stack TupleHash/TupleHashXOF using one required compiled kernel.
///
/// Requires `strict-tuplehash-acceleration`, GNU/Linux x86-64 AVX2 or little-endian
/// AArch64 NEON/SHA3, and a deployment guaranteeing those features throughout
/// execution. Static admission is not runtime detection or a migration monitor.
/// Authority, startup tests, framing, item writers and XOF state stay on the
/// preacquired protected stack. Secret results stay in protected mappings.
/// Backend/invariant/resource failure after arming and recoverable worker unwind
/// quarantine permanently; invalid input and cooperative cancellation permit reuse.
/// No fallback, authority export or reset. Qualification and retest remain pending;
/// caller input, privileged snapshots, interruptions and abort remain outside the
/// bounded owned-memory contract. Scalar [`Session`] remains independently usable.
///
/// ```compile_fail
/// fn bound<T: Send>() {} bound::<brynja_crypto_cpu_std::strict_tuplehash::CompiledSession>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {} bound::<brynja_crypto_cpu_std::strict_tuplehash::CompiledSession>();
/// ```
/// ```compile_fail
/// fn bound<T: Copy>() {} bound::<brynja_crypto_cpu_std::strict_tuplehash::CompiledSession>();
/// ```
/// ```compile_fail
/// fn bound<T: Clone>() {} bound::<brynja_crypto_cpu_std::strict_tuplehash::CompiledSession>();
/// ```
/// ```compile_fail
/// fn bound<T: core::fmt::Debug>() {} bound::<brynja_crypto_cpu_std::strict_tuplehash::CompiledSession>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu_std::strict_tuplehash::{CompiledSession, Output, Error};
/// fn escape(s: &mut CompiledSession) -> Result<Output<'static>, Error> { s.hash(&[], b"") }
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu_std::strict_tuplehash::{CompiledSession, Error};
/// fn overlap(s: &mut CompiledSession) -> Result<(), Error> {
///     let out = s.hash(&[], b"")?; s.quarantine(); let _ = out.expose(); Ok(())
/// }
/// ```
/// ```no_run
/// use brynja_crypto_cpu_std::strict_tuplehash::*;
/// fn example(items: &[Item<'_>], kernel: Kernel, limits: Limits) -> Result<(), Error> {
///     // Caller establishes the full compiled-feature deployment guarantee first.
///     let mut session = CompiledSession::new(Algorithm::TupleHash128(256), kernel, limits)?;
///     let output = session.hash(items, b"application")?;
///     assert_eq!(output.expose().len(), 32);
///     Ok(())
/// }
/// ```
pub struct CompiledSession {
    inner: Session,
    kernel: Kernel,
    quarantined: bool,
    #[cfg(test)]
    fault: tests::Fault,
}
impl CompiledSession {
    /// Preacquires stack and buffers, then runs startup tests on the protected stack.
    pub fn new(algorithm: Algorithm, kernel: Kernel, limits: Limits) -> Result<Self, Error> {
        super::require_target()?;
        compatible(kernel)?;
        kernel.check_compiled_target().map_err(Error::Backend)?;
        let mut inner = Session::new(algorithm, limits)?;
        let mut result = Err(Error::Invariant);
        inner.stack.run(|| result = worker::probe(kernel))?;
        result?;
        Ok(Self {
            inner,
            kernel,
            quarantined: false,
            #[cfg(test)]
            fault: tests::Fault::None,
        })
    }
    /// Exact public construction and output width, never private tuple metadata.
    pub const fn algorithm(&self) -> Algorithm {
        self.inner.algorithm
    }
    /// Required kernel identity, not qualification evidence.
    pub const fn kernel(&self) -> Kernel {
        self.kernel
    }
    /// Irreversible wrapper-local health, not process-wide revocation.
    pub const fn is_quarantined(&self) -> bool {
        self.quarantined
    }
    /// Clears forgotten output and prevents all future requests.
    pub fn quarantine(&mut self) {
        self.quarantined = true;
        self.inner.output.clear();
        self.inner.staging.clear();
    }
    /// Complete tuple with byte customization; item boundaries are significant.
    pub fn hash(&mut self, items: &[Item<'_>], customization: &[u8]) -> Result<Output<'_>, Error> {
        self.compute(items, Bits::bytes(customization), &Cancellation::new())
    }
    /// Bounded canonical-bit request. Content is checked only on the protected
    /// worker; item lengths are derived, never independently supplied. Output is
    /// returned only after joining and clearing the worker stack and staging.
    pub fn compute(
        &mut self,
        items: &[Item<'_>],
        customization: Bits<'_>,
        cancel: &Cancellation,
    ) -> Result<Output<'_>, Error> {
        self.inner.output.clear();
        self.inner.staging.clear();
        if self.quarantined {
            return Err(Error::Quarantined);
        }
        super::validate(self.inner.limits, items, &customization)?;
        cancel.check()?;
        let mut guard = Buffers {
            output: &mut self.inner.output,
            staging: &mut self.inner.staging,
            keep_output: false,
        };
        self.quarantined = true;
        let operation = worker::Operation {
            algorithm: self.inner.algorithm,
            kernel: self.kernel,
            items,
            customization,
            cancel,
            #[cfg(test)]
            fault: self.fault,
        };
        let destination = guard
            .output
            .as_bytes_mut()
            .get_mut(..self.inner.algorithm.output_bytes())
            .ok_or(Error::Invariant)?;
        let staging = guard.staging.as_bytes_mut();
        let mut result = Err(Error::Invariant);
        self.inner
            .stack
            .run(|| result = worker::run(operation, staging, destination))?;
        if matches!(result, Ok(()) | Err(Error::Cancelled | Error::InvalidBits)) {
            self.quarantined = false;
        }
        result?;
        cancel.check()?;
        guard.keep_output = true;
        drop(guard);
        Ok(Output {
            output: &mut self.inner.output,
            algorithm: self.inner.algorithm,
        })
    }
}
fn compatible(kernel: Kernel) -> Result<(), Error> {
    if matches!(kernel, Kernel::X86Keccak | Kernel::ArmKeccak) {
        Ok(())
    } else {
        Err(Error::Backend(
            brynja_crypto_cpu::static_execution::Error::WrongOperation,
        ))
    }
}
