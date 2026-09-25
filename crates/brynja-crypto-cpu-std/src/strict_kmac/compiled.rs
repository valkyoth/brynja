use super::{
    Algorithm, Bits, Buffers, Cancellation, Error, Limits, Output, Request, Session,
    require_target, validate,
};
pub use brynja_crypto_cpu::static_execution::Kernel;
#[cfg(test)]
mod tests;
mod worker;

/// Explicit protected KMAC/KMACXOF acceleration, never a scalar fallback.
///
/// Requires `strict-kmac-acceleration`, native supported GNU/Linux protections,
/// and the exact kernel's complete build-wide bundle (AVX2 or Arm NEON/SHA3).
/// Establish compatible CPU/OS support throughout deployment; static features
/// are not runtime detection, affinity or a migration guarantee. Scalar [`Session`]
/// is unchanged. Authority, startup checks, keyed sponge and verification are
/// constructed only on the protected worker; staging/output have protected owners.
/// Backend/invariant/worker failures permanently quarantine this wrapper. Invalid
/// requests, cancellation and a well-formed tag mismatch preserve reuse.
/// No reset, exported authority or whole-process/interruption/abort erasure claim.
/// New compiler/native qualification and independent retest remain pending.
///
/// ```no_run
/// use brynja_crypto_cpu_std::strict_kmac::{Algorithm, CompiledSession, Kernel, Limits, Error};
/// // Build with -C target-feature=+avx2 and establish compatible deployment.
/// let mut session = CompiledSession::new(Algorithm::Kmac256(256), Kernel::X86Keccak, Limits {
///     stack_bytes: 262144, max_stack_mapping_bytes: 1048576,
///     max_buffer_mapping_bytes: 65536, max_message_bits: 8192,
///     max_setup_bits: 4096, max_output_bits: 4096, max_chunks: 16,
/// })?;
/// let output = session.authenticate(&[0x42; 32], b"message", b"domain")?;
/// assert_eq!(output.expose().len(), 32); // explicit secret borrow, not declassification
/// drop(output);
/// # Ok::<(), Error>(())
/// ```
/// ```compile_fail
/// fn bound<T: Send>() {} bound::<brynja_crypto_cpu_std::strict_kmac::CompiledSession>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {} bound::<brynja_crypto_cpu_std::strict_kmac::CompiledSession>();
/// ```
/// ```compile_fail
/// fn bound<T: Copy>() {} bound::<brynja_crypto_cpu_std::strict_kmac::CompiledSession>();
/// ```
/// ```compile_fail
/// fn bound<T: Clone>() {} bound::<brynja_crypto_cpu_std::strict_kmac::CompiledSession>();
/// ```
/// ```compile_fail
/// fn bound<T: core::fmt::Debug>() {} bound::<brynja_crypto_cpu_std::strict_kmac::CompiledSession>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu_std::strict_kmac::{CompiledSession, Output, Error};
/// fn escape(s: &mut CompiledSession) -> Result<Output<'static>, Error> { s.authenticate(&[0;32], b"", b"") }
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu_std::strict_kmac::{CompiledSession, Error};
/// fn overlap(s: &mut CompiledSession) -> Result<(), Error> {
///     let out = s.authenticate(&[0;32], b"", b"")?; s.quarantine(); let _ = out.expose(); Ok(())
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
    /// Preacquires all resources and checks the exact backend on the protected stack.
    pub fn new(algorithm: Algorithm, kernel: Kernel, limits: Limits) -> Result<Self, Error> {
        require_target()?;
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
    /// Public construction/width, never retained key or private accumulated state.
    pub const fn algorithm(&self) -> Algorithm {
        self.inner.algorithm
    }
    /// Exact selected kernel, not qualification evidence.
    pub const fn kernel(&self) -> Kernel {
        self.kernel
    }
    /// Irreversible wrapper-local health, not global revocation.
    pub const fn is_quarantined(&self) -> bool {
        self.quarantined
    }
    /// Disables future computation and clears both mappings, including forgotten loans.
    pub fn quarantine(&mut self) {
        self.quarantined = true;
        self.inner.output.clear();
        self.inner.staging.clear();
    }
    /// Complete byte request. Returned output remains secret until declassified.
    pub fn authenticate(
        &mut self,
        key: &[u8],
        input: &[u8],
        customization: &[u8],
    ) -> Result<Output<'_>, Error> {
        self.compute(
            Request {
                key: Bits::bytes(key),
                customization: Bits::bytes(customization),
                chunks: &[input],
                tail: Bits::empty(),
            },
            &Cancellation::new(),
        )
    }
    /// Complete arbitrary-bit request using [`Session::compute`]'s public bounds
    /// and cancellation intervals. Setup/fixed finalization are bounded but not
    /// internally interruptible. Errors clear staging/output after workers join.
    /// Backend/invariant/panic and launch/resource failures permanently quarantine.
    pub fn compute(
        &mut self,
        request: Request<'_>,
        cancel: &Cancellation,
    ) -> Result<Output<'_>, Error> {
        self.execute(request, None, cancel)?;
        Ok(Output {
            output: &mut self.inner.output,
            algorithm: self.inner.algorithm,
        })
    }
    /// Verifies on the protected stack; only the authentication decision escapes.
    /// Same full-strength, exact-bit-width policy as [`Session::verify`]. Equal-width
    /// canonical comparison has no content-dependent exit. All computed output is
    /// cleared even on success/mismatch; a mismatch does not quarantine the session.
    pub fn verify(
        &mut self,
        request: Request<'_>,
        candidate: Bits<'_>,
        cancel: &Cancellation,
    ) -> Result<bool, Error> {
        self.execute(request, Some(candidate), cancel)?
            .ok_or(Error::Invariant)
    }
    fn execute(
        &mut self,
        request: Request<'_>,
        candidate: Option<Bits<'_>>,
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
            keep_output: false,
        };
        validate(
            self.inner.algorithm,
            self.inner.limits,
            &request,
            candidate.as_ref(),
        )?;
        cancel.check()?;
        let verifying = candidate.is_some();
        self.quarantined = true;
        let destination = guard
            .output
            .as_bytes_mut()
            .get_mut(..self.inner.algorithm.output_bytes())
            .ok_or(Error::Invariant)?;
        let operation = worker::Operation {
            algorithm: self.inner.algorithm,
            kernel: self.kernel,
            request,
            candidate,
            cancel,
            #[cfg(test)]
            fault: self.fault,
        };
        let mut result = Err(Error::Invariant);
        let staging = guard.staging.as_bytes_mut();
        self.inner
            .stack
            .run(|| result = worker::run(operation, staging, destination))?;
        match result {
            Ok(value) => {
                if value.is_some() != verifying {
                    return Err(Error::Invariant);
                }
                self.quarantined = false;
                cancel.check()?;
                guard.keep_output = !verifying;
                Ok(value)
            }
            Err(error @ (Error::Cancelled | Error::InvalidBits)) => {
                self.quarantined = false;
                Err(error)
            }
            Err(error) => Err(error),
        }
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
