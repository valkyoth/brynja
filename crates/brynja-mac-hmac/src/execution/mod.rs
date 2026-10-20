//! Explicit static-CPU HMAC over hardened, erasing hash owners only.
//!
//! Enable `hardened-execution` and the complete build-wide target features.
//! Deployment must ensure those instructions and OS register state remain
//! available for the owner's lifetime. This API does not detect CPU features,
//! pin threads or guarantee safe VM migration. Use the portable `crate::Hmac`
//! when that deployment guarantee cannot be established.
//!
//! No preferred-route or failure-driven fallback, ordinary hash import, generic
//! callback, state export or accumulated-message-length query is provided.
//! This is NOT a protected-memory API. It does not erase caller buffers, compiler
//! moves/spills, OS snapshots or fatal-abort state. HMAC-specific qualification
//! and independent review remain pending.

mod adapter;
mod backends;
mod retained;
#[cfg(test)]
#[path = "../../tests/execution/lifecycle.rs"]
mod tests;

use crate::{Error, SecretTag, Tag, Verification, engine::Engine};
use adapter::Adapter;
pub use brynja_crypto_cpu::static_execution::{Authority, Kernel};
use retained::Retained;

/// Sealed supported identity for borrowed static CPU execution.
pub trait Algorithm<'a>: crate::Algorithm + backends::Backend<'a> {}
impl<'a, A: crate::Algorithm + backends::Backend<'a>> Algorithm<'a> for A {}

/// Affine HMAC bound to one authority for normalization, inner and outer hashes.
///
/// Default HMAC constructors never select this path. Route observations cannot
/// create authority. Backend failure or recoverable unwinding clears both hash
/// owners, not just the inner stream. Expected length rejection preserves it.
///
/// ```compile_fail
/// fn send<T: Send>() {}
/// send::<brynja_mac_hmac::execution::Hmac<'static, brynja_mac_hmac::Sha256>>();
/// ```
/// ```compile_fail
/// fn clone<T: Clone>() {}
/// clone::<brynja_mac_hmac::execution::Hmac<'static, brynja_mac_hmac::Sha256>>();
/// ```
pub struct Hmac<'a, A: Algorithm<'a>> {
    engine: Retained<Engine<Adapter<'a, A>>>,
    kernel: Kernel,
    _local: core::marker::PhantomData<*mut ()>,
}

impl<'a, A: Algorithm<'a>> Hmac<'a, A> {
    /// Requires this authority; every required hash owner is admitted before
    /// reading key bytes. No error causes portable fallback.
    pub fn from_static(owner: &'a Authority, key: &[u8]) -> Result<Self, Error> {
        Self::create(owner, key, A::TAG_BYTES)
    }

    /// Selects an exact whole-byte tag prefix before accepting a key.
    pub fn from_static_with_tag_length(
        owner: &'a Authority,
        key: &[u8],
        tag_bytes: usize,
    ) -> Result<Self, Error> {
        if tag_bytes.checked_mul(8).ok_or(Error::TagLength)? > A::TAG_BITS {
            return Err(Error::TagLength);
        }
        Self::create(owner, key, tag_bytes)
    }

    fn create(owner: &'a Authority, key: &[u8], tag_bytes: usize) -> Result<Self, Error> {
        A::validate()?;
        if !crate::policy::valid_tag_length(A::TAG_BYTES, tag_bytes) {
            return Err(Error::TagLength);
        }
        // These states are all empty. Returning from any admission failure
        // drops every previously constructed owner, before key absorption.
        let first = A::create(owner)?;
        let second = A::create(owner)?;
        let third = if key.len() > A::BLOCK_BYTES {
            Some(A::create(owner)?)
        } else {
            None
        };
        let mut states = [Some(first), Some(second), third].into_iter().flatten();
        let engine = Engine::new_with(key, tag_bytes, || states.next().ok_or(Error::SecretMemory))?;
        Ok(Self {
            engine: Retained::new(engine),
            kernel: owner.report().kernel,
            _local: core::marker::PhantomData,
        })
    }

    /// Selected kernel only, not a work count, health certificate or authority.
    pub const fn kernel(&self) -> Kernel {
        self.kernel
    }

    /// Empty updates recheck backend health too. Errors other than an atomic
    /// message-length rejection, and recoverable unwinding, clear both owners.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        self.engine.update(|engine| engine.update(input))
    }

    /// Consumes this state; errors preserve the public destination.
    pub fn finalize_tag(self, output: &mut [u8]) -> Result<Tag<'_, A>, Error> {
        self.engine.take()?.public(None, output).map(Tag::rebind)
    }

    /// Every error clears the whole destination, including terminal rejection.
    pub fn finalize_secret(self, output: &mut [u8]) -> Result<SecretTag<'_, A>, Error> {
        match self.engine.take() {
            Ok(engine) => engine.secret(None, output).map(SecretTag::rebind),
            Err(error) => {
                let _ = brynja_core::clear_owned_region(output);
                Err(error)
            }
        }
    }

    /// Consumes and compares all equal-length candidate bytes without fallback.
    pub fn verify(self, candidate: &[u8]) -> Result<Verification, Error> {
        self.engine.take()?.verify(None, candidate)
    }

    /// Final SHA-2 high bits or SHA-3 low bits; public errors are transactional.
    pub fn finalize_bits_tag<'out>(
        self,
        input: A::FinalInput<'_>,
        output: &'out mut [u8],
    ) -> Result<Tag<'out, A>, Error> {
        self.engine
            .take()?
            .public(Some(input), output)
            .map(Tag::rebind)
    }

    /// Consuming exact final bits with clearing secret-output ownership.
    pub fn finalize_bits_secret<'out>(
        self,
        input: A::FinalInput<'_>,
        output: &'out mut [u8],
    ) -> Result<SecretTag<'out, A>, Error> {
        match self.engine.take() {
            Ok(engine) => engine.secret(Some(input), output).map(SecretTag::rebind),
            Err(error) => {
                let _ = brynja_core::clear_owned_region(output);
                Err(error)
            }
        }
    }

    /// Consumes the exact final bits and verifies the preselected tag width.
    pub fn verify_bits(
        self,
        input: A::FinalInput<'_>,
        candidate: &[u8],
    ) -> Result<Verification, Error> {
        self.engine.take()?.verify(Some(input), candidate)
    }

    /// Consumes and clears all HMAC/hash state without output.
    pub fn cancel(self) {}
}
