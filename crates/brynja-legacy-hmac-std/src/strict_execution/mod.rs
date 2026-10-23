//! Protected scalar legacy HMAC on native GNU/Linux x86-64/little-endian AArch64.
//!
//! Acquires guarded, resident, dump/fork-excluded worker, staging and output
//! mappings before accepting keys. A fresh joined worker creates and consumes
//! the entire HMAC computation on that stack; the host clears it after joining.
//! No arbitrary callback, secret-bearing thread return or ordinary-memory
//! fallback is exposed. Portable hardened hash code is used even when dependency
//! features enable acceleration. These are legacy-only, not FIPS-approved APIs.
//!
//! Caller buffers/copies, compiler registers, TLS/panic hooks, privileged
//! snapshots, hibernation and fatal termination remain outside this boundary.
//! Deployment must forbid fork, external protection revocation and native thread
//! cancellation while resources live. Stack sizes are not worst-case proofs.
//! This initial implementation requires its own independent review/qualification.
use brynja_crypto_cpu_std::protected_memory::{ProtectedBytes, ProtectedStack};
pub use brynja_legacy_hmac::{Algorithm, LegacyUse, Md5, Sha1};
use core::marker::PhantomData;
#[cfg(test)]
mod tests;
mod types;
mod worker;
pub use types::{Bits, Cancellation, Error, Limits, PublicDeclassification, Request, TagPolicy};

/// Reusable protected resources, never retained keyed state. A forgotten output
/// loan cannot disable session-owned clearing on reuse, errors or destruction.
/// ```compile_fail
/// fn bound<T: Send>() {}
/// bound::<brynja_legacy_hmac_std::strict_execution::Session<brynja_legacy_hmac_std::strict_execution::Sha1>>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {}
/// bound::<brynja_legacy_hmac_std::strict_execution::Session<brynja_legacy_hmac_std::strict_execution::Md5>>();
/// ```
pub struct Session<A: Algorithm> {
    stack: ProtectedStack,
    staging: ProtectedBytes,
    output: ProtectedBytes,
    bytes: usize,
    limits: Limits,
    identity: PhantomData<fn() -> A>,
    #[cfg(test)]
    fault: tests::Fault,
}
impl<A: Algorithm> Session<A> {
    /// Requires explicit legacy acknowledgement and preacquires all resources.
    /// Unsupported platforms/models or failed protections return errors only.
    pub fn new(_ack: LegacyUse, policy: TagPolicy, limits: Limits) -> Result<Self, Error> {
        let bytes = policy.bytes::<A>()?;
        if limits.max_chunks == 0 {
            return Err(Error::InvalidLimits);
        }
        let stack = ProtectedStack::new(limits.stack_bytes, limits.max_stack_mapping_bytes)?;
        let staging = ProtectedBytes::new(bytes, limits.max_buffer_mapping_bytes)?;
        let output = ProtectedBytes::new(bytes, limits.max_buffer_mapping_bytes)?;
        Ok(Self {
            stack,
            staging,
            output,
            bytes,
            limits,
            identity: PhantomData,
            #[cfg(test)]
            fault: tests::Fault::None,
        })
    }
    /// Public preselected width, never an accumulated private message length.
    pub const fn tag_bytes(&self) -> usize {
        self.bytes
    }
    /// Complete byte request; input buffers remain caller-owned.
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
    /// Bounded chunks plus a canonical high-bit tail. Key setup/finalization are
    /// bounded but not internally cancellable; updates check every 4096 bytes.
    /// A cancellation racing after the final host check may still complete.
    pub fn compute(
        &mut self,
        request: Request<'_>,
        cancel: &Cancellation,
    ) -> Result<Output<'_, A>, Error> {
        self.execute(request, None, cancel)?;
        Ok(Output {
            storage: &mut self.output,
            identity: PhantomData,
        })
    }
    /// Compares the preselected width on the protected worker and releases only
    /// the final decision. Wrong-width candidates are rejected before key use.
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
        self.output.clear();
        self.staging.clear();
        let mut buffers = Buffers {
            output: &mut self.output,
            staging: &mut self.staging,
            keep: false,
        };
        types::validate(self.limits, &request, candidate, self.bytes)?;
        cancel.check()?;
        let bytes = self.bytes;
        let verifying = candidate.is_some();
        let destination = buffers.output.as_bytes_mut();
        let staging = buffers.staging.as_bytes_mut();
        let mut result = Err(Error::Invariant);
        #[cfg(test)]
        let fault = self.fault;
        self.stack.run(|| {
            #[cfg(test)]
            tests::configure(fault);
            result = worker::run::<A>(bytes, request, candidate, cancel, staging, destination);
        })?;
        let result = result?;
        cancel.check()?;
        if result.is_some() != verifying {
            return Err(Error::Invariant);
        }
        buffers.keep = !verifying;
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

/// Affine secret output loan, bound to the exact legacy algorithm and session.
/// ```compile_fail
/// use brynja_legacy_hmac_std::strict_execution::{Session, Sha1, Output, Error};
/// fn escape(s: &mut Session<Sha1>) -> Result<Output<'static, Sha1>, Error> { s.authenticate(b"key", b"message") }
/// ```
/// ```compile_fail
/// use brynja_legacy_hmac_std::strict_execution::{Session, Md5, Error};
/// fn reuse(s: &mut Session<Md5>) -> Result<(), Error> {
///     let first = s.authenticate(b"key", b"a")?;
///     let second = s.authenticate(b"key", b"b")?;
///     let _ = (first.expose(), second.expose()); Ok(())
/// }
pub struct Output<'a, A: Algorithm> {
    storage: &'a mut ProtectedBytes,
    identity: PhantomData<fn() -> A>,
}
impl<A: Algorithm> Output<'_, A> {
    /// Explicit borrowed secret exposure. Copies become the caller's responsibility.
    pub fn expose(&self) -> &[u8] {
        self.storage.as_bytes()
    }
    /// Releases the selected tag, clearing the retained mapping on return.
    /// Wrong-width destinations remain unchanged; the secret still clears.
    pub fn declassify(self, output: &mut [u8], _ack: PublicDeclassification) -> Result<(), Error> {
        if output.len() != self.storage.as_bytes().len() {
            return Err(Error::OutputLength);
        }
        output.copy_from_slice(self.expose());
        Ok(())
    }
}
impl<A: Algorithm> Drop for Output<'_, A> {
    fn drop(&mut self) {
        self.storage.clear();
    }
}
