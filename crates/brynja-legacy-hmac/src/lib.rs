//! Explicit legacy-only HMAC-SHA-1 and HMAC-MD5 compatibility.
//!
//! Do not select these algorithms for new protocols. This package is not a
//! modern algorithm provider, FIPS approved service, or protocol negotiator.
//! Its distinct sealed identities cannot implement the modern HMAC contract.
//! Existing hardened hash owners clear their owned storage, but this new
//! composition still needs its own compiler, timing and independent review.
//! No register, spill, caller-buffer, paging, dump or fatal-abort guarantee is
//! inferred from destruction. No protected-memory or acceleration is promised.

#![no_std]

mod algorithms;
mod engine;
mod output;
mod scratch;

pub use algorithms::{Algorithm, Md5, Sha1};
pub use brynja_legacy_sha1::{BitString, BitStringError};
pub use output::{SecretTag, Tag, Verification};

/// Value-free failure from a legacy HMAC operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// The underlying digest's checked message domain would be exceeded.
    MessageTooLong,
    /// The preselected tag size or supplied destination/candidate is invalid.
    TagLength,
    /// Secret storage or a private composition invariant failed.
    SecretMemory,
}

impl From<brynja_core::SecretMemoryError> for Error {
    fn from(_: brynja_core::SecretMemoryError) -> Self {
        Self::SecretMemory
    }
}

/// Explicit caller assertion that a historical protocol requires legacy HMAC.
///
/// This is acknowledgement, not proof of provenance, security or policy approval.
pub struct LegacyUse(());

impl LegacyUse {
    /// Acknowledges legacy compatibility use; never authorizes modern negotiation.
    pub const fn acknowledge() -> Self {
        Self(())
    }
}

/// Affine, local legacy HMAC state with consuming finalization and verification.
///
/// No key export, reset, snapshot, ordinary hash conversion or modern adapter.
/// Rejected updates leave the state unchanged; finalization always consumes it.
/// Message/key lengths remain public. Callers must enforce workload and failed
/// verification limits, and supply unpredictable keys; empty keys are accepted
/// mathematically but are not secure.
///
/// ```compile_fail
/// fn send<T: Send>() {}
/// send::<brynja_legacy_hmac::Hmac<brynja_legacy_hmac::Sha1>>();
/// ```
/// ```compile_fail
/// fn sync<T: Sync>() {}
/// sync::<brynja_legacy_hmac::Hmac<brynja_legacy_hmac::Md5>>();
/// ```
/// ```compile_fail
/// use brynja_legacy_hmac::{Hmac, Md5, LegacyUse};
/// let state = Hmac::<Md5>::new(LegacyUse::acknowledge(), b"example").unwrap();
/// let _copy = state.clone();
/// ```
/// ```compile_fail
/// use brynja_legacy_hmac::{Hmac, Sha1, LegacyUse};
/// let state = Hmac::<Sha1>::new(LegacyUse::acknowledge(), b"example").unwrap();
/// println!("{state:?}");
/// ```
/// ```compile_fail
/// use brynja_legacy_hmac::{Hmac, Sha1, LegacyUse};
/// let state = Hmac::<Sha1>::new(LegacyUse::acknowledge(), b"key").unwrap();
/// state.cancel();
/// state.verify(&[0; 20]).unwrap();
/// ```
pub struct Hmac<A: Algorithm> {
    engine: engine::Engine<A>,
    local: core::marker::PhantomData<*mut ()>,
}

impl<A: Algorithm> Hmac<A> {
    /// Creates a full-length legacy tag owner (20 bytes SHA-1, 16 bytes MD5).
    pub fn new(acknowledgement: LegacyUse, key: &[u8]) -> Result<Self, Error> {
        Self::with_tag_length(acknowledgement, key, A::TAG_BYTES)
    }

    /// Selects a byte-prefix tag of 10 bytes (80 bits) through the full length.
    ///
    /// This legacy-only floor follows RFC 2104 section 5 and admits RFC 2202's
    /// 96-bit examples. It does not relax modern HMAC's policy. Select the width
    /// from a trusted protocol configuration, never from a received tag length.
    pub fn with_tag_length(_: LegacyUse, key: &[u8], tag_bytes: usize) -> Result<Self, Error> {
        Ok(Self {
            engine: engine::Engine::new(key, tag_bytes)?,
            local: core::marker::PhantomData,
        })
    }

    /// Absorbs complete bytes without exposing accumulated message length.
    pub fn update(&mut self, message: &[u8]) -> Result<(), Error> {
        self.engine.update(message)
    }

    /// Authenticates bytes with a full-length public tag; errors preserve output.
    pub fn authenticate<'a>(
        acknowledgement: LegacyUse,
        key: &[u8],
        message: &[u8],
        output: &'a mut [u8],
    ) -> Result<Tag<'a, A>, Error> {
        let mut state = Self::new(acknowledgement, key)?;
        state.update(message)?;
        state.finalize_tag(output)
    }

    /// Consumes this state and explicitly releases a public tag.
    /// Every failure preserves the destination.
    pub fn finalize_tag(self, output: &mut [u8]) -> Result<Tag<'_, A>, Error> {
        self.engine.public(None, output)
    }

    /// Consumes a canonical high-bit-order final message into a public tag.
    pub fn finalize_bits_tag<'out>(
        self,
        tail: BitString<'_>,
        output: &'out mut [u8],
    ) -> Result<Tag<'out, A>, Error> {
        self.engine.public(Some(tail), output)
    }

    /// Consumes this state into clearing secret output. Errors clear all output.
    pub fn finalize_secret(self, output: &mut [u8]) -> Result<SecretTag<'_, A>, Error> {
        self.engine.secret(None, output)
    }

    /// Consumes a canonical high-bit-order final message into clearing output.
    pub fn finalize_bits_secret<'out>(
        self,
        tail: BitString<'_>,
        output: &'out mut [u8],
    ) -> Result<SecretTag<'out, A>, Error> {
        self.engine.secret(Some(tail), output)
    }

    /// Consumes this state and compares exactly the preselected tag length.
    /// Equal-length comparison accumulates every byte difference.
    pub fn verify(self, candidate: &[u8]) -> Result<Verification, Error> {
        self.engine.verify(None, candidate)
    }

    /// Consumes a canonical high-bit-order final message and verifies its tag.
    pub fn verify_bits(self, tail: BitString<'_>, candidate: &[u8]) -> Result<Verification, Error> {
        self.engine.verify(Some(tail), candidate)
    }

    /// Consumes and clears this state without producing an authenticator.
    pub fn cancel(self) {}
}

#[doc = include_str!("../README.md")]
mod readme {}
