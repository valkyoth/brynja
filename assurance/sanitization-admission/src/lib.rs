#![no_std]
#![forbid(unsafe_code)]

//! Review-only candidate for the future adapter ownership boundary.
//!
//! This crate is a non-production, unpublished, independent Cargo workspace.
//! It proves that the frozen adapter shape compiles without activating an
//! upstream feature or transitive package. It is not `brynja-sanitization` and
//! exposes no protocol integration.

use core::fmt;
use sanitization::SecretBytes;

/// Payload-free failure accepted from a caller-provided byte source.
///
/// Callers must clear any source-specific sensitive error state before
/// collapsing it into this closed boundary value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceFailure;

/// Closed failure from the review-only candidate boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateError {
    /// Empty storage is not admitted as a secret owner.
    EmptySecret,
    /// A caller generator failed; its value is deliberately discarded.
    SourceFailure,
}

/// Opaque adapter-owned fixed-size candidate storage.
///
/// This type deliberately has no `Clone`, `Copy`, conversion, extraction,
/// `Deref`, or foreign-trait bridge.
///
/// ```compile_fail
/// use brynja_sanitization_admission_fixture::CandidateSecret;
///
/// let secret = CandidateSecret::<4>::try_from_fn(|index| index as u8).unwrap();
/// let _copy = secret.clone();
/// ```
pub struct CandidateSecret<const N: usize> {
    inner: SecretBytes<N>,
}

impl<const N: usize> CandidateSecret<N> {
    /// Construct directly in upstream owned storage after rejecting `N == 0`.
    pub fn try_from_fn(make_byte: impl FnMut(usize) -> u8) -> Result<Self, CandidateError> {
        if N == 0 {
            return Err(CandidateError::EmptySecret);
        }
        Ok(Self {
            inner: SecretBytes::from_fn(make_byte),
        })
    }

    /// Fallible direct construction with a payload-free source error.
    ///
    /// Rich or secret-bearing source errors cannot cross this boundary.
    ///
    /// ```compile_fail
    /// use brynja_sanitization_admission_fixture::CandidateSecret;
    ///
    /// let _ = CandidateSecret::<4>::try_from_fallible(|_| Err([0xA5; 16]));
    /// ```
    pub fn try_from_fallible(
        make_byte: impl FnMut(usize) -> Result<u8, SourceFailure>,
    ) -> Result<Self, CandidateError> {
        if N == 0 {
            return Err(CandidateError::EmptySecret);
        }
        SecretBytes::try_from_fn(make_byte)
            .map(|inner| Self { inner })
            .map_err(|SourceFailure| CandidateError::SourceFailure)
    }

    /// Replace transactionally after a complete candidate is ready.
    ///
    /// ```compile_fail
    /// use brynja_sanitization_admission_fixture::CandidateSecret;
    ///
    /// let mut secret = CandidateSecret::<4>::try_from_fn(|_| 1).unwrap();
    /// let _ = secret.try_replace_from_fallible(|_| Err([0xA5; 16]));
    /// ```
    pub fn try_replace_from_fallible(
        &mut self,
        make_byte: impl FnMut(usize) -> Result<u8, SourceFailure>,
    ) -> Result<(), CandidateError> {
        self.inner
            .try_replace_from_fn(make_byte)
            .map_err(|SourceFailure| CandidateError::SourceFailure)
    }

    /// Inspect through a closure without returning a borrow.
    pub fn inspect<R>(&self, inspect: impl FnOnce(&[u8; N]) -> R) -> R {
        self.inner.expose_secret(inspect)
    }

    /// Clear the complete fixed-size storage explicitly.
    pub fn clear(&mut self) {
        self.inner.secure_clear();
    }
}

impl<const N: usize> fmt::Debug for CandidateSecret<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CandidateSecret")
            .field("len", &N)
            .field("contents", &"<redacted>")
            .finish()
    }
}
