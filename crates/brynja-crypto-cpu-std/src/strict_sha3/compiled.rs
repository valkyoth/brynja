use super::{
    Algorithm, Bits, Cancellation, Digest, Error, Limits, OutputGuard, Session, require_target,
    validate_request,
};
pub use brynja_crypto_cpu::static_execution::Kernel;
#[cfg(test)]
mod tests;
mod worker;

/// Explicit protected-stack SHA-3/SHAKE/cSHAKE acceleration, without fallback.
///
/// Requires `strict-sha3-acceleration` and the complete build-wide feature bundle:
/// x86 AVX2, or Arm NEON/SHA3. Deploy only with compatible CPU/OS support throughout
/// execution. Static features are not runtime detection, affinity, or a migration
/// guarantee. Unsupported strict targets/models reject; scalar [`Session`] is
/// unchanged. All authority, startup checks, scoped state and output staging are
/// created and consumed on protected worker stacks, never transported as results.
/// Backend/invariant failure or worker panic permanently quarantines this wrapper.
/// Cancellation and invalid public input preserve reuse. No reset or authority export.
/// Compiler/native qualification and independent retest remain pending. This does
/// not promise whole-process, signal, register-interruption or abort erasure.
///
/// ```no_run
/// use brynja_crypto_cpu_std::strict_sha3::{Algorithm, CompiledSession, Kernel, Limits, Error};
/// // Build with -C target-feature=+avx2 and establish compatible deployment.
/// let mut session = CompiledSession::new(Algorithm::Shake256(257), Kernel::X86Keccak, Limits {
///     stack_bytes: 262144, max_stack_mapping_bytes: 1048576,
///     max_output_mapping_bytes: 65536, max_message_bits: 8192,
///     max_customization_bits: 1024, max_output_bits: 4096, max_chunks: 16,
/// })?;
/// let digest = session.hash(b"abc")?;
/// assert_eq!(digest.expose().len(), 33);
/// drop(digest);
/// # Ok::<(), Error>(())
/// ```
/// ```compile_fail
/// fn bound<T: Send>() {} bound::<brynja_crypto_cpu_std::strict_sha3::CompiledSession>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {} bound::<brynja_crypto_cpu_std::strict_sha3::CompiledSession>();
/// ```
/// ```compile_fail
/// fn bound<T: Copy>() {} bound::<brynja_crypto_cpu_std::strict_sha3::CompiledSession>();
/// ```
/// ```compile_fail
/// fn bound<T: Clone>() {} bound::<brynja_crypto_cpu_std::strict_sha3::CompiledSession>();
/// ```
/// ```compile_fail
/// fn bound<T: core::fmt::Debug>() {} bound::<brynja_crypto_cpu_std::strict_sha3::CompiledSession>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu_std::strict_sha3::{CompiledSession, Digest, Error};
/// fn escape(s: &mut CompiledSession) -> Result<Digest<'static>, Error> { s.hash(b"") }
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu_std::strict_sha3::{CompiledSession, Error};
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
    /// Preacquires resources and tests the required kernel on the protected stack.
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
    /// Public identity and exact output size, never accumulated private state.
    pub const fn algorithm(&self) -> Algorithm {
        self.inner.algorithm
    }
    /// Exact required kernel, not independent/native qualification evidence.
    pub const fn kernel(&self) -> Kernel {
        self.kernel
    }
    /// Irreversible wrapper-local health, not process-wide revocation.
    pub const fn is_quarantined(&self) -> bool {
        self.quarantined
    }
    /// Prevents future requests and clears forgotten output loans.
    pub fn quarantine(&mut self) {
        self.quarantined = true;
        self.inner.output.clear();
    }
    /// Complete byte input, empty cSHAKE N/S, and protected output ownership.
    pub fn hash(&mut self, input: &[u8]) -> Result<Digest<'_>, Error> {
        self.hash_chunks(&[input], Bits::empty(), &Cancellation::new())
    }
    /// Byte chunks and a canonical LSB-first tail, with empty N/S.
    pub fn hash_chunks(
        &mut self,
        chunks: &[&[u8]],
        tail: Bits<'_>,
        cancel: &Cancellation,
    ) -> Result<Digest<'_>, Error> {
        self.hash_customized_chunks(chunks, tail, Bits::empty(), Bits::empty(), cancel)
    }
    /// Same public bounds, bit convention and cancellation intervals as
    /// [`Session::hash_customized_chunks`]. Invalid input/cancellation preserves
    /// health. Backend/invariant/worker/resource failures after launch is armed
    /// permanently quarantine. All started workers join and output clears before
    /// any error returns. N/S canonicality is checked only on the protected stack.
    pub fn hash_customized_chunks(
        &mut self,
        chunks: &[&[u8]],
        tail: Bits<'_>,
        name: Bits<'_>,
        customization: Bits<'_>,
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
            &tail,
            &name,
            &customization,
        )?;
        cancel.check()?;
        let mut transaction = OutputGuard {
            output: &mut self.inner.output,
            complete: false,
        };
        self.quarantined = true;
        let request = worker::Request {
            algorithm: self.inner.algorithm,
            kernel: self.kernel,
            chunks,
            tail,
            name,
            customization,
            cancel,
            #[cfg(test)]
            fault: self.fault,
        };
        let destination = transaction
            .output
            .as_bytes_mut()
            .get_mut(..self.inner.algorithm.output_bytes())
            .ok_or(Error::Invariant)?;
        let mut result = Err(Error::Invariant);
        self.inner
            .stack
            .run(|| result = worker::run(request, destination))?;
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
fn compatible(kernel: Kernel) -> Result<(), Error> {
    if matches!(kernel, Kernel::X86Keccak | Kernel::ArmKeccak) {
        Ok(())
    } else {
        Err(Error::Backend(
            brynja_crypto_cpu::static_execution::Error::WrongOperation,
        ))
    }
}
