//! Explicit hardened SHA-1 HMAC execution for legacy compatibility only.
//!
//! This is not ordinary hash execution, modern/FIPS algorithm admission or a
//! protected-memory API. The supplied executor must already have accelerated
//! authority. Its platform provider must guarantee the complete instruction
//! bundle on every schedulable CPU for the executor's lifetime. Cached detection
//! is not a live migration monitor. No constructor or operation falls back.
//! Portable `crate::Hmac` remains portable even when this feature is unified.
//!
//! Source-owned memory clears on Drop and recoverable unwind. Caller copies,
//! compiler frames/spills, OS snapshots and fatal abort remain outside this
//! composition's guarantee; its compiler/native qualification is pending.

mod adapter;
mod retained;

use crate::{BitString, Error, LegacyUse, SecretTag, Sha1, Tag, Verification, engine::Engine};
use adapter::Sha1Adapter;
pub use brynja_legacy_sha1::hardened_execution::Mode as Sha1Mode;
pub use brynja_legacy_sha1::{Sha1Backend, hardened_execution::Executor as Sha1Executor};
use retained::Retained;

/// Affine, thread-local HMAC-SHA-1 bound to one borrowed hardened executor.
///
/// ```compile_fail
/// fn send<T: Send>() {}
/// send::<brynja_legacy_hmac::execution::Sha1Hmac<'static>>();
/// ```
/// ```compile_fail
/// fn sync<T: Sync>() {}
/// sync::<brynja_legacy_hmac::execution::Sha1Hmac<'static>>();
/// ```
/// ```compile_fail
/// fn clone<T: Clone>() {}
/// clone::<brynja_legacy_hmac::execution::Sha1Hmac<'static>>();
/// ```
/// ```compile_fail
/// fn debug<T: core::fmt::Debug>() {}
/// debug::<brynja_legacy_hmac::execution::Sha1Hmac<'static>>();
/// ```
pub struct Sha1Hmac<'a> {
    engine: Retained<Engine<Sha1Adapter<'a>>>,
    backend: Sha1Backend,
    local: core::marker::PhantomData<*mut ()>,
}

impl<'a> Sha1Hmac<'a> {
    /// Requires accelerated authority before reading the key; full 20-byte tag.
    pub fn new(
        acknowledgement: LegacyUse,
        executor: &'a Sha1Executor,
        key: &[u8],
    ) -> Result<Self, Error> {
        Self::with_tag_length(acknowledgement, executor, key, 20)
    }

    /// Preselects a 10–20-byte tag and admits all empty hash owners before keys.
    /// Ordinary or portable executors cannot authorize accelerated composition.
    pub fn with_tag_length(
        _: LegacyUse,
        executor: &'a Sha1Executor,
        key: &[u8],
        tag_bytes: usize,
    ) -> Result<Self, Error> {
        if !(10..=20).contains(&tag_bytes) {
            return Err(Error::TagLength);
        }
        let backend = executor
            .report()
            .backend
            .ok_or(Error::ExecutionUnavailable)?;
        // The report is not authority: each real stream independently admits
        // through start(), before Engine receives key bytes. All streams borrow
        // the same executor for subsequent checks and irreversible revocation.
        let first = executor.start().map_err(adapter::error)?;
        let second = executor.start().map_err(adapter::error)?;
        let third = if key.len() > 64 {
            Some(executor.start().map_err(adapter::error)?)
        } else {
            None
        };
        let mut streams = [Some(first), Some(second), third].into_iter().flatten();
        let engine =
            Engine::new_with(key, tag_bytes, || streams.next().ok_or(Error::SecretMemory))?;
        Ok(Self {
            engine: Retained::new(engine),
            backend,
            local: core::marker::PhantomData,
        })
    }

    /// Non-authorizing identity, not a work count or health certificate.
    pub const fn backend(&self) -> Sha1Backend {
        self.backend
    }

    /// Checks health even for empty input. Fatal errors/unwind clear both owners;
    /// an atomic length rejection preserves them. No error selects fallback.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        self.engine.update(|engine| engine.update(input))
    }

    /// Consumes the owner. Errors preserve the public destination.
    pub fn finalize_tag(self, output: &mut [u8]) -> Result<Tag<'_, Sha1>, Error> {
        self.engine.take()?.public(None, output).map(Tag::rebind)
    }

    /// Consumes canonical high-order final bits into a transactional public tag.
    pub fn finalize_bits_tag<'out>(
        self,
        tail: BitString<'_>,
        output: &'out mut [u8],
    ) -> Result<Tag<'out, Sha1>, Error> {
        self.engine
            .take()?
            .public(Some(tail), output)
            .map(Tag::rebind)
    }

    /// Consumes into a clearing tag. Every error clears the entire destination.
    pub fn finalize_secret(self, output: &mut [u8]) -> Result<SecretTag<'_, Sha1>, Error> {
        self.secret(None, output)
    }

    /// Consumes final bits into clearing output, including on terminal errors.
    pub fn finalize_bits_secret<'out>(
        self,
        tail: BitString<'_>,
        output: &'out mut [u8],
    ) -> Result<SecretTag<'out, Sha1>, Error> {
        self.secret(Some(tail), output)
    }

    fn secret<'out>(
        self,
        tail: Option<BitString<'_>>,
        output: &'out mut [u8],
    ) -> Result<SecretTag<'out, Sha1>, Error> {
        match self.engine.take() {
            Ok(engine) => engine.secret(tail, output).map(SecretTag::rebind),
            Err(error) => {
                let _ = brynja_core::clear_owned_region(output);
                Err(error)
            }
        }
    }

    /// Consumes and compares every equal-length candidate byte without fallback.
    pub fn verify(self, candidate: &[u8]) -> Result<Verification, Error> {
        self.engine.take()?.verify(None, candidate)
    }

    /// Consumes final bits and verifies the preselected tag width.
    pub fn verify_bits(self, tail: BitString<'_>, candidate: &[u8]) -> Result<Verification, Error> {
        self.engine.take()?.verify(Some(tail), candidate)
    }

    /// Consumes all key-derived state without producing a tag.
    pub fn cancel(self) {}
}
