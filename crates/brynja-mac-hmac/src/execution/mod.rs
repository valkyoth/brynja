//! Explicit CPU-authorized HMAC over hardened, erasing hash owners only.
//!
//! Static constructors require `hardened-execution` and the complete build-wide
//! target features. Runtime constructors require `runtime-execution` and an
//! existing platform authority; they do not require globally enabled target
//! features. Both require CPU instructions and OS register state to remain
//! available for the owner's lifetime. This leaf does not detect features,
//! pin threads or guarantee safe VM migration. Use portable `crate::Hmac`
//! when the applicable deployment guarantee cannot be established.
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
mod tests;

use crate::{Error, SecretTag, Tag, engine::Engine};
use adapter::Adapter;
use backends::Source;
#[cfg(feature = "runtime-execution")]
pub use brynja_crypto_cpu::runtime_execution::Authority as RuntimeAuthority;
pub use brynja_crypto_cpu::static_execution::{Authority, Kernel};
use retained::Retained;

/// Sealed supported identity for borrowed static or runtime CPU execution.
pub trait Algorithm<'a>: crate::Algorithm + backends::Backend<'a> {}
impl<'a, A: crate::Algorithm + backends::Backend<'a>> Algorithm<'a> for A {}

/// Affine HMAC bound to one authority for normalization, inner and outer hashes.
///
/// Default HMAC constructors never select this route. Route observations cannot
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
        Self::create(Source::Static(owner), key, A::TAG_BYTES)
    }

    /// Selects an exact whole-byte tag prefix before accepting a key.
    pub fn from_static_with_tag_length(
        owner: &'a Authority,
        key: &[u8],
        tag_bytes: usize,
    ) -> Result<Self, Error> {
        crate::validate_tag_policy::<A>(Some(tag_bytes))?;
        Self::create(Source::Static(owner), key, tag_bytes)
    }

    /// Borrows already established platform-wide authority, not a copied report.
    /// Prefer the safe hosted adapter; creating low-level runtime authority
    /// requires the provider to uphold its CPU/OS migration contract.
    #[cfg(feature = "runtime-execution")]
    pub fn from_runtime(
        owner: &'a brynja_crypto_cpu::runtime_execution::Authority,
        key: &[u8],
    ) -> Result<Self, Error> {
        Self::create(Source::Runtime(owner), key, A::TAG_BYTES)
    }

    /// Runtime authority with an exact, preselected whole-byte tag prefix.
    #[cfg(feature = "runtime-execution")]
    pub fn from_runtime_with_tag_length(
        owner: &'a brynja_crypto_cpu::runtime_execution::Authority,
        key: &[u8],
        tag_bytes: usize,
    ) -> Result<Self, Error> {
        crate::validate_tag_policy::<A>(Some(tag_bytes))?;
        Self::create(Source::Runtime(owner), key, tag_bytes)
    }

    fn create(owner: Source<'a>, key: &[u8], tag_bytes: usize) -> Result<Self, Error> {
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
            kernel: owner.kernel(),
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
    /// Only a match returns `Ok(())`; a mismatch returns [`Error::Mismatch`].
    ///
    /// # Errors
    ///
    /// A mismatch rejects this request; do not retry verification or fall back.
    /// Other errors do not authenticate and must not select a weaker route.
    /// The protocol must enforce failed-attempt and per-key usage budgets.
    pub fn verify(self, candidate: &[u8]) -> Result<(), Error> {
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
    ///
    /// # Errors
    ///
    /// A completed mismatch is [`Error::Mismatch`], never successful authentication.
    /// A mismatch rejects this request; do not retry verification or fall back.
    /// Other errors do not authenticate and must not select a weaker route.
    /// The protocol must enforce failed-attempt and per-key usage budgets.
    pub fn verify_bits(self, input: A::FinalInput<'_>, candidate: &[u8]) -> Result<(), Error> {
        self.engine.take()?.verify(Some(input), candidate)
    }

    /// Consumes and clears all HMAC/hash state without output.
    pub fn cancel(self) {}
}
