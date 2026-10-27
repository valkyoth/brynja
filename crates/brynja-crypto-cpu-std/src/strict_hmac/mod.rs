//! Opt-in protected scalar HMAC; development implementation, qualification pending.
//!
//! GNU/Linux x86-64/little-endian AArch64 native builds only. All mappings are
//! acquired before key/message input. Secret state is constructed on a joined,
//! guarded, resident and dump-excluded worker stack, cleared after termination.
//! Output/staging are separate protected mappings. No ordinary-stack fallback,
//! custom callbacks or retained keyed state. Default sessions never select CPU
//! acceleration, even if other dependencies enable accelerated hash features.
//!
//! Caller inputs/copies, compiler registers, signal frames, TLS/panic hooks,
//! privileged snapshots and fatal termination remain outside this guarantee.
//! Fork, native cancellation and external mapping revocation are unsupported.
//! A minimum stack size is not a worst-case stack bound. No certification,
//! whole-process erasure or independent qualification is claimed.
//!
//! ```no_run
//! use brynja_crypto_cpu_std::strict_hmac::{Session, Sha256, TagPolicy, Limits, Error};
//! let mut session = Session::<Sha256>::new(TagPolicy::Full, Limits {
//!     stack_bytes: 262144, max_stack_mapping_bytes: 1048576,
//!     max_buffer_mapping_bytes: 65536, max_key_bytes: 4096,
//!     max_message_bits: 65536, max_chunks: 16,
//! })?;
//! let output = session.authenticate(&[0x42; 32], b"message")?;
//! assert_eq!(output.bit_len(), 256);
//! drop(output); // clears retained protected storage
//! # Ok::<(), Error>(())
//! ```
use crate::protected_memory::{ProtectedBytes, ProtectedStack};
use core::marker::PhantomData;
#[cfg(feature = "strict-hmac-acceleration")]
mod compiled;
#[cfg(test)]
mod tests;
mod types;
mod worker;
pub use brynja_mac_hmac::{
    Sha3_224, Sha3_256, Sha3_384, Sha3_512, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256,
    Sha512T,
};
#[cfg(feature = "strict-hmac-acceleration")]
pub use compiled::{CompiledSession, Kernel};
pub use types::{Bits, Cancellation, Error, Limits, PublicDeclassification, Request, TagPolicy};

/// Sealed modern HMAC identity, not a downstream digest implementation hook.
pub trait Algorithm: brynja_mac_hmac::Algorithm + worker::Backend {}
impl<A: brynja_mac_hmac::Algorithm + worker::Backend> Algorithm for A {}

/// Reusable protected resources, not a live keyed HMAC state.
///
/// ```compile_fail
/// fn bound<T: Send>() {}
/// bound::<brynja_crypto_cpu_std::strict_hmac::Session<brynja_crypto_cpu_std::strict_hmac::Sha256>>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {}
/// bound::<brynja_crypto_cpu_std::strict_hmac::Session<brynja_crypto_cpu_std::strict_hmac::Sha256>>();
/// ```
pub struct Session<A: Algorithm> {
    stack: ProtectedStack,
    staging: ProtectedBytes,
    output: ProtectedBytes,
    policy: TagPolicy,
    bits: usize,
    limits: Limits,
    _algorithm: PhantomData<fn() -> A>,
    #[cfg(test)]
    fault: tests::Fault,
}
impl<A: Algorithm> Session<A> {
    /// Validates public policy and preacquires stack, staging and output.
    /// Empty/predictable keys are not secure; this API cannot prove key entropy.
    pub fn new(policy: TagPolicy, limits: Limits) -> Result<Self, Error> {
        let bits = policy.bits::<A>()?;
        if limits.max_chunks == 0 {
            return Err(Error::InvalidLimits);
        }
        let stack = ProtectedStack::new(limits.stack_bytes, limits.max_stack_mapping_bytes)?;
        let bytes = bits.div_ceil(8);
        let staging = ProtectedBytes::new(bytes, limits.max_buffer_mapping_bytes)?;
        let output = ProtectedBytes::new(bytes, limits.max_buffer_mapping_bytes)?;
        Ok(Self {
            stack,
            staging,
            output,
            policy,
            bits,
            limits,
            _algorithm: PhantomData,
            #[cfg(test)]
            fault: tests::Fault::None,
        })
    }
    /// Exact public tag policy; not an accumulated secret-message length.
    pub const fn tag_bits(&self) -> usize {
        self.bits
    }

    /// Byte-aligned complete request. Result stays secret until explicit release.
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
    /// Computes a bounded complete request on the protected worker.
    /// Key setup/finalization are bounded but not internally cancellable;
    /// message processing checks at 4096-byte boundaries. A cancellation racing
    /// after the final host check can still complete. Errors/unwind clear buffers.
    pub fn compute(
        &mut self,
        request: Request<'_>,
        cancel: &Cancellation,
    ) -> Result<Output<'_, A>, Error> {
        self.execute(request, None, cancel)?;
        Ok(Output {
            storage: &mut self.output,
            bits: self.bits,
            _algorithm: PhantomData,
        })
    }
    /// Compares on the protected worker and releases only the decision.
    /// Candidate length must equal the preselected width. Full general tags
    /// compare canonical unused bits too; a noncanonical candidate cannot match.
    ///
    /// # Errors
    ///
    /// A completed [`Error::Mismatch`] permits session reuse for other requests,
    /// not acceptance of this one. Reuse does not reset a protocol's attempt budget.
    /// A mismatch rejects this request; do not retry verification or fall back.
    /// Other errors do not authenticate and must not select a weaker route.
    /// The protocol must enforce failed-attempt and per-key usage budgets.
    pub fn verify(
        &mut self,
        request: Request<'_>,
        candidate: &[u8],
        cancel: &Cancellation,
    ) -> Result<(), Error> {
        // execute validates the worker result and restores reusable health before
        // converting a completed mismatch into an authentication error.
        match self.execute(request, Some(candidate), cancel)? {
            Some(true) => Ok(()),
            Some(false) => Err(Error::Mismatch),
            None => Err(Error::Invariant),
        }
    }
    fn execute(
        &mut self,
        request: Request<'_>,
        candidate: Option<&[u8]>,
        cancel: &Cancellation,
    ) -> Result<Option<bool>, Error> {
        self.output.clear();
        self.staging.clear();
        let mut guard = Buffers {
            output: &mut self.output,
            staging: &mut self.staging,
            keep: false,
        };
        types::validate(self.limits, &request, candidate, self.bits.div_ceil(8))?;
        cancel.check()?;
        let policy = self.policy;
        let verifying = candidate.is_some();
        let destination = guard.output.as_bytes_mut();
        let staging = guard.staging.as_bytes_mut();
        let mut result = Err(Error::Invariant);
        #[cfg(test)]
        let fault = self.fault;
        self.stack.run(|| {
            #[cfg(test)]
            tests::configure(fault);
            result = worker::run::<A>(policy, request, candidate, cancel, staging, destination);
        })?;
        let result = result?;
        cancel.check()?;
        if result.is_some() != verifying {
            return Err(Error::Invariant);
        }
        guard.keep = !verifying;
        Ok(result)
    }
}
struct Buffers<'a> {
    output: &'a mut ProtectedBytes,
    staging: &'a mut ProtectedBytes,
    keep: bool,
}
impl Drop for Buffers<'_> {
    fn drop(&mut self) {
        self.staging.clear();
        if !self.keep {
            self.output.clear();
        }
    }
}

/// Exclusive typed secret loan; dropping it clears the retained output.
/// Forgetting it cannot disable clearing at session reuse or destruction.
///
/// ```compile_fail
/// use brynja_crypto_cpu_std::strict_hmac::{Session, Sha256, Output, Error};
/// fn escape(session: &mut Session<Sha256>) -> Result<Output<'static, Sha256>, Error> {
///     session.authenticate(b"key", b"message")
/// }
/// ```
pub struct Output<'a, A: Algorithm> {
    storage: &'a mut ProtectedBytes,
    bits: usize,
    _algorithm: PhantomData<fn() -> A>,
}
impl<A: Algorithm> Output<'_, A> {
    /// Public selected width, including a general digest's partial byte.
    pub const fn bit_len(&self) -> usize {
        self.bits
    }
    /// Explicit borrowed secret access; caller copies are outside this owner.
    pub fn expose(&self) -> &[u8] {
        self.storage.as_bytes()
    }
    /// Releases the selected tag; a width error preserves the public destination
    /// and still clears this secret loan.
    pub fn declassify(
        self,
        destination: &mut [u8],
        _authority: PublicDeclassification,
    ) -> Result<(), Error> {
        if destination.len() != self.storage.as_bytes().len() {
            return Err(Error::OutputLength);
        }
        destination.copy_from_slice(self.expose());
        Ok(())
    }
}
impl<A: Algorithm> Drop for Output<'_, A> {
    fn drop(&mut self) {
        self.storage.clear();
    }
}
