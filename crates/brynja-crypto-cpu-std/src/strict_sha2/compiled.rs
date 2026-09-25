use super::{
    Algorithm, Cancellation, Digest, Error, Limits, OutputGuard, Session, require_target,
    validate_request,
};
pub use brynja_crypto_cpu::static_execution::Kernel;
#[cfg(test)]
mod tests;
mod worker;

/// Explicit protected-stack hardware SHA-2, never an automatic scalar fallback.
///
/// Requires `strict-sha2-acceleration` and the kernel's complete build-wide target
/// feature bundle. Deploy only on compatible CPUs with the required OS register
/// state throughout execution; compilation is not runtime detection, affinity,
/// or a migration guarantee. Unsupported strict targets/models still reject.
/// The scalar [`Session`] constructor is unchanged by enabling this feature.
///
/// Each request creates and consumes authority, KAT scratch, scoped hash state
/// and digest staging on its protected stack. Only public outcomes cross join.
/// Backend/invariant failure or worker panic permanently quarantines this wrapper;
/// cancellation and invalid public input do not. No reset or authority export.
/// New compiler/native qualification and independent review remain pending.
/// This does not claim whole-process, signal, register-interruption or abort erasure.
///
/// ```no_run
/// use brynja_crypto_cpu_std::strict_sha2::{Algorithm, CompiledSession, Kernel, Limits, Error};
/// // x86 example: build with -C target-feature=+sha,+sse2 and deploy accordingly.
/// let mut session = CompiledSession::new(Algorithm::Sha256, Kernel::X86Sha256, Limits {
///     stack_bytes: 262144, max_stack_mapping_bytes: 1048576,
///     max_output_mapping_bytes: 65536, max_message_bits: 8192, max_chunks: 16,
/// })?;
/// let digest = session.hash(b"abc")?;
/// assert_eq!(digest.expose().len(), 32);
/// drop(digest);
/// # Ok::<(), Error>(())
/// ```
/// ```compile_fail
/// fn bound<T: Send>() {} bound::<brynja_crypto_cpu_std::strict_sha2::CompiledSession>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {} bound::<brynja_crypto_cpu_std::strict_sha2::CompiledSession>();
/// ```
/// ```compile_fail
/// fn bound<T: Copy>() {} bound::<brynja_crypto_cpu_std::strict_sha2::CompiledSession>();
/// ```
/// ```compile_fail
/// fn bound<T: Clone>() {} bound::<brynja_crypto_cpu_std::strict_sha2::CompiledSession>();
/// ```
/// ```compile_fail
/// fn bound<T: core::fmt::Debug>() {} bound::<brynja_crypto_cpu_std::strict_sha2::CompiledSession>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu_std::strict_sha2::{CompiledSession, Digest, Error};
/// fn escape(s: &mut CompiledSession) -> Result<Digest<'static>, Error> { s.hash(b"") }
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu_std::strict_sha2::{CompiledSession, Error};
/// fn overlap(s: &mut CompiledSession) -> Result<(), Error> {
///     let digest = s.hash(b"abc")?; s.quarantine(); let _ = digest.expose(); Ok(())
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
    /// Preacquires protected resources and tests the required exact backend on
    /// the protected stack before accepting a request. Never substitutes a route.
    pub fn new(algorithm: Algorithm, kernel: Kernel, limits: Limits) -> Result<Self, Error> {
        require_target()?;
        compatible(algorithm, kernel)?;
        kernel.check_compiled_target().map_err(Error::Backend)?;
        let mut inner = Session::new(algorithm, limits)?;
        let mut result = Err(Error::Invariant);
        inner.stack.run(|| {
            result = worker::probe(kernel);
        })?;
        result?;
        Ok(Self {
            inner,
            kernel,
            quarantined: false,
            #[cfg(test)]
            fault: tests::Fault::None,
        })
    }
    /// Fixed public identity, never private accumulated state.
    pub const fn algorithm(&self) -> Algorithm {
        self.inner.algorithm
    }
    /// Exact selected kernel; not independent/native qualification evidence.
    pub const fn kernel(&self) -> Kernel {
        self.kernel
    }
    /// Irreversible wrapper-local health, not process-wide revocation.
    pub const fn is_quarantined(&self) -> bool {
        self.quarantined
    }
    /// Prevents all future requests and clears any forgotten output loan.
    pub fn quarantine(&mut self) {
        self.quarantined = true;
        self.inner.output.clear();
    }
    /// Complete borrowed byte input, with protected output ownership.
    pub fn hash(&mut self, input: &[u8]) -> Result<Digest<'_>, Error> {
        self.hash_chunks(&[input], &[], 0, &Cancellation::new())
    }
    /// Same public bounds, bit convention and cancellation intervals as
    /// [`Session::hash_chunks`]. Preflight rejection/cancellation preserves health.
    /// Failures after worker entry quarantine unless they are ordinary cancellation
    /// or invalid input. Protection/worker launch failures conservatively quarantine
    /// too. All workers join and output clears before any failure returns.
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
        validate_request(
            self.inner.algorithm,
            self.inner.limits,
            chunks,
            tail.len(),
            valid_bits,
        )?;
        cancel.check()?;
        let mut transaction = OutputGuard {
            output: &mut self.inner.output,
            complete: false,
        };
        // Arm before launch: even coordinator unwind cannot revive the wrapper.
        self.quarantined = true;
        let mut result = Err(Error::Invariant);
        let request = worker::Request {
            algorithm: self.inner.algorithm,
            kernel: self.kernel,
            chunks,
            tail,
            valid_bits,
            cancel,
            #[cfg(test)]
            fault: self.fault,
        };
        let destination = transaction.output.as_bytes_mut();
        self.inner.stack.run(|| {
            result = worker::run(request, destination);
        })?;
        if matches!(result, Ok(()) | Err(Error::Cancelled | Error::InvalidBits)) {
            self.quarantined = false;
        }
        result?;
        cancel.check()?;
        transaction.complete = true;
        drop(transaction);
        Ok(Digest {
            output: &mut self.inner.output,
            algorithm: self.inner.algorithm,
        })
    }
}
fn compatible(algorithm: Algorithm, kernel: Kernel) -> Result<(), Error> {
    let narrow = matches!(algorithm, Algorithm::Sha224 | Algorithm::Sha256);
    if matches!(
        (narrow, kernel),
        (true, Kernel::X86Sha256 | Kernel::ArmSha256)
            | (false, Kernel::X86Sha512 | Kernel::ArmSha512)
    ) {
        Ok(())
    } else {
        Err(Error::Backend(
            brynja_crypto_cpu::static_execution::Error::WrongOperation,
        ))
    }
}
