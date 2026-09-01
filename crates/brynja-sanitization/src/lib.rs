//! Optional fixed-size secret storage for Brynja callers.
//!
//! This separately selected downstream adapter owns
//! [`sanitization::SecretBytes`] and copies explicitly to or from
//! [`brynja_core`] caller-owned regions. No Brynja facade or protocol engine
//! activates it. It is outside every FIPS validated-module boundary.

#![no_std]

use brynja_core::{OwnedSecretRegion, SecretRegionInitialization};
use core::fmt;
use sanitization::SecretBytes;

/// Payload-free failure accepted from a caller-provided byte source.
///
/// Callers must clear source-specific error state before collapsing it into
/// this closed value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceFailure;

/// Closed, value-free failure from the adapter boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SanitizationError {
    /// A zero-byte container cannot own a secret.
    EmptySecret,
    /// A source failed after collapsing its error into [`SourceFailure`].
    SourceFailure,
    /// A Brynja region did not have exactly the fixed secret length.
    RegionLengthMismatch,
    /// Brynja rejected initialization of the destination region.
    RegionInitialization,
}

/// Opaque, non-copyable fixed-size secret storage.
///
/// The type deliberately implements no `Clone`, `Copy`, `Deref`, `AsRef`,
/// `From`, `Into`, serialization, or foreign-trait bridge. Debug output is
/// always redacted.
///
/// ```compile_fail
/// use brynja_sanitization::SanitizedSecret;
/// let secret = SanitizedSecret::<4>::try_from_fn(|index| index as u8).unwrap();
/// let _copy = secret.clone();
/// ```
///
/// ```compile_fail
/// use brynja_sanitization::SanitizedSecret;
/// let _ = SanitizedSecret::<4>::try_from_fallible(|_| Err([0xA5; 16]));
/// ```
///
/// ```compile_fail
/// use brynja_sanitization::SanitizedSecret;
/// let secret = SanitizedSecret::<4>::try_from_fn(|_| 7).unwrap();
/// let _: &[u8] = secret.as_ref();
/// ```
///
/// ```compile_fail
/// use brynja_sanitization::SanitizedSecret;
/// let secret = SanitizedSecret::<4>::try_from_fn(|_| 7).unwrap();
/// let escaped: &[u8; 4] = secret.inspect(|bytes| bytes);
/// drop(secret);
/// let _ = escaped;
/// ```
#[must_use = "secret storage must remain live or be explicitly cleared"]
pub struct SanitizedSecret<const N: usize> {
    inner: SecretBytes<N>,
}

#[cfg(test)]
mod assurance_contract;

impl<const N: usize> SanitizedSecret<N> {
    /// Constructs directly in owned storage and rejects `N == 0`.
    pub fn try_from_fn(make_byte: impl FnMut(usize) -> u8) -> Result<Self, SanitizationError> {
        if N == 0 {
            return Err(SanitizationError::EmptySecret);
        }
        Ok(Self {
            inner: SecretBytes::from_fn(make_byte),
        })
    }

    /// Constructs fallibly using the only admitted payload-free source error.
    pub fn try_from_fallible(
        make_byte: impl FnMut(usize) -> Result<u8, SourceFailure>,
    ) -> Result<Self, SanitizationError> {
        if N == 0 {
            return Err(SanitizationError::EmptySecret);
        }
        SecretBytes::try_from_fn(make_byte)
            .map(|inner| Self { inner })
            .map_err(|SourceFailure| SanitizationError::SourceFailure)
    }

    /// Replaces the whole secret only after complete candidate construction.
    pub fn try_replace_from_fallible(
        &mut self,
        make_byte: impl FnMut(usize) -> Result<u8, SourceFailure>,
    ) -> Result<(), SanitizationError> {
        self.inner
            .try_replace_from_fn(make_byte)
            .map_err(|SourceFailure| SanitizationError::SourceFailure)
    }

    /// Copies one exact Brynja-owned region into new adapter storage.
    pub fn try_copy_from_brynja(source: &OwnedSecretRegion<'_>) -> Result<Self, SanitizationError> {
        if N == 0 {
            return Err(SanitizationError::EmptySecret);
        }
        if source.expose().len() != N {
            return Err(SanitizationError::RegionLengthMismatch);
        }
        Self::try_from_fallible(|index| source.expose().get(index).copied().ok_or(SourceFailure))
    }

    /// Copies into and returns one exact caller-owned Brynja region.
    ///
    /// Failure clears the complete destination through Brynja's initialization
    /// state. Success leaves two separately owned copies; each owner clears its
    /// own storage independently.
    pub fn copy_into_brynja<'region>(
        &self,
        destination: &'region mut [u8],
    ) -> Result<OwnedSecretRegion<'region>, SanitizationError> {
        let exact_length = destination.len() == N;
        let mut initialization = SecretRegionInitialization::begin(destination)
            .map_err(|_| SanitizationError::RegionInitialization)?;
        if !exact_length {
            return Err(SanitizationError::RegionLengthMismatch);
        }
        self.inner
            .expose_secret(|bytes| initialization.write(bytes))
            .map_err(|_| SanitizationError::RegionInitialization)?;
        initialization
            .finish()
            .map_err(|_| SanitizationError::RegionInitialization)
    }

    /// Inspects bytes only for the duration of a caller closure.
    pub fn inspect<R>(&self, inspect: impl FnOnce(&[u8; N]) -> R) -> R {
        self.inner.expose_secret(inspect)
    }

    /// Clears the fixed-size storage immediately and consumes the owner.
    pub fn clear(mut self) {
        self.inner.secure_clear();
    }
}

impl<const N: usize> fmt::Debug for SanitizedSecret<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SanitizedSecret")
            .field("len", &N)
            .field("contents", &"<redacted>")
            .finish()
    }
}

/// Whether the v0.11.2 adapter boundary is implemented.
pub const SANITIZATION_ADAPTER_IMPLEMENTED: bool = true;
