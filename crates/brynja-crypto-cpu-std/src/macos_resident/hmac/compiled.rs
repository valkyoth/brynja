use super::{
    Algorithm, Bits, Buffers, Cancellation, Error, Limits, Output, Request, Session, TagPolicy,
    types,
};
pub use brynja_crypto_cpu::static_execution::Kernel;
use core::marker::PhantomData;
#[cfg(test)]
mod tests;
mod worker;

/// Explicit compiled acceleration with resident resources; no scalar fallback.
///
/// Requires native Apple Silicon macOS residency and the selected kernel's
/// complete build-wide target features. Establish matching CPU/OS support for
/// the entire deployment before construction. Static features are not detection,
/// affinity or a VM-migration guarantee. Authority and keyed state are created
/// only on the resident worker; no authority is moved from the caller stack.
///
/// Backend, internal and worker failures permanently quarantine this wrapper.
/// Pre-entry thread setup failures, invalid requests, cancellation and tag
/// mismatch preserve reuse. A setup error does not authorize fallback. Scalar
/// [`Session`] remains scalar, including with feature unification. Caller copies,
/// registers, OS diagnostic storage, interruption and fatal abort remain outside
/// the owned-storage guarantee. Compiler/native qualification is pending.
/// This resident profile does not exclude core dumps and is not strict admission.
///
/// ```compile_fail
/// fn send<T: Send>() {}
/// send::<brynja_crypto_cpu_std::macos_resident::hmac::CompiledSession<brynja_crypto_cpu_std::macos_resident::hmac::Sha256>>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu_std::macos_resident::hmac::{CompiledSession, Sha256, Output, Error};
/// fn escape(s: &mut CompiledSession<Sha256>) -> Result<Output<'static, Sha256>, Error> {
///     s.authenticate(b"key", b"message")
/// }
/// ```
pub struct CompiledSession<A: Algorithm + for<'a> brynja_mac_hmac::execution::Algorithm<'a>> {
    inner: Session<A>,
    kernel: Kernel,
    quarantined: bool,
}
impl<A: Algorithm + for<'a> brynja_mac_hmac::execution::Algorithm<'a>> CompiledSession<A> {
    /// Preacquires resources and probes the exact backend on the resident stack
    /// before any caller key is accepted.
    pub fn new(policy: TagPolicy, kernel: Kernel, limits: Limits) -> Result<Self, Error> {
        compatible::<A>(kernel)?;
        kernel.check_compiled_target().map_err(Error::Backend)?;
        let mut inner = Session::<A>::new(policy, limits)?;
        let mut result = Err(Error::Invariant);
        inner.stack.run(|| result = worker::probe::<A>(kernel))?;
        result?;
        Ok(Self {
            inner,
            kernel,
            quarantined: false,
        })
    }
    /// Exact selected kernel; not native qualification or authority.
    pub const fn kernel(&self) -> Kernel {
        self.kernel
    }
    /// Public preselected tag width.
    pub const fn tag_bits(&self) -> usize {
        self.inner.bits
    }
    /// Wrapper-local terminal health; not a global revocation mechanism.
    pub const fn is_quarantined(&self) -> bool {
        self.quarantined
    }
    /// Permanently disables requests and clears retained output, even forgotten loans.
    pub fn quarantine(&mut self) {
        self.quarantined = true;
        self.inner.output.clear();
        self.inner.staging.clear();
    }
    /// Byte-aligned complete request; output remains a secret loan.
    pub fn authenticate(&mut self, key: &[u8], message: &[u8]) -> Result<Output<'_, A>, Error> {
        self.compute(
            Request {
                key,
                chunks: &[message],
                tail: Bits::empty(),
            },
            &Cancellation::new(),
        )
    }
    /// Same limits and cancellation granularity as [`Session::compute`].
    /// No initialization/execution error authorizes scalar fallback.
    pub fn compute(
        &mut self,
        request: Request<'_>,
        cancel: &Cancellation,
    ) -> Result<Output<'_, A>, Error> {
        self.execute(request, None, cancel)?;
        Ok(Output {
            storage: &mut self.inner.output,
            bits: self.inner.bits,
            _algorithm: PhantomData,
        })
    }
    /// Compares the exact selected width on the resident worker.
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
        types::validate(
            self.inner.limits,
            &request,
            candidate,
            self.inner.bits.div_ceil(8),
        )?;
        cancel.check()?;
        let verifying = candidate.is_some();
        self.quarantined = true;
        let policy = self.inner.policy;
        let kernel = self.kernel;
        let staging = guard.staging.bytes_mut();
        let destination = guard.output.bytes_mut();
        #[cfg(test)]
        let fault = self.inner.fault;
        #[cfg(test)]
        let ranges =
            super::super::test_storage::ranges_for_worker(&self.inner.stack, staging, destination);
        let mut result = Err(Error::Invariant);
        let launch = self.inner.stack.run(|| {
            #[cfg(test)]
            super::super::test_storage::configure(ranges);
            #[cfg(test)]
            super::tests::configure(fault);
            result = worker::run::<A>(
                kernel,
                policy,
                request,
                candidate,
                cancel,
                staging,
                destination,
            );
        });
        if let Err(error) = launch {
            // These resource errors occur before pthread_create succeeds: the
            // worker never entered. Panic/protocol errors remain terminal.
            if matches!(
                error,
                crate::macos_resident::Error::ThreadStart
                    | crate::macos_resident::Error::ThreadAttributes
            ) {
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
                | Error::Mac(brynja_mac_hmac::Error::MessageTooLong)),
            ) => {
                self.quarantined = false;
                Err(error)
            }
            Err(error) => Err(error),
        }
    }
}

fn compatible<A: Algorithm>(kernel: Kernel) -> Result<(), Error> {
    let valid = match A::BLOCK_BYTES {
        64 => matches!(kernel, Kernel::ArmSha256),
        128 => matches!(kernel, Kernel::ArmSha512),
        // The sealed SHA-3 identities have these exact rates.
        144 | 136 | 104 | 72 => matches!(kernel, Kernel::ArmKeccak),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(Error::Backend(
            brynja_crypto_cpu::static_execution::Error::WrongOperation,
        ))
    }
}
