//! Non-secret TLS failure domains.
//!
//! Failure values do not carry arbitrary text, byte slices, provider-native
//! codes, cryptographic material, or formatting implementations.

use crate::{Alert, AlertClass, ProviderFailure, ResourceExhaustion};

/// A protocol alert that is known to represent a failure.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct AlertFailure(Alert);

/// A local failure that has not yet been mapped to a wire alert.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum LocalFailure {
    /// A local configuration violated an invariant.
    InvalidConfiguration,
    /// Input violated a protocol or API invariant.
    InvalidInput,
    /// An operation was attempted in the wrong state.
    InvalidState,
    /// A required capability was unavailable.
    MissingCapability,
    /// An internal invariant failed closed.
    InternalInvariant,
}

/// A typed TLS failure with no secret-bearing formatting surface.
///
/// Orderly close and explicit cancellation are deliberately not variants.
///
/// ```compile_fail
/// use brynja_core::{LocalFailure, TlsFailure};
/// let failure = TlsFailure::Local(LocalFailure::InvalidInput);
/// let _ = format!("{failure:?}");
/// ```
///
/// ```compile_fail
/// use brynja_core::{LocalFailure, TlsFailure};
/// let secret = [7_u8; 32];
/// let _ = TlsFailure::Local(LocalFailure::InvalidInput, secret);
/// ```
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum TlsFailure {
    /// A version-aware protocol alert failure.
    Alert(AlertFailure),
    /// A provider-independent local failure.
    Local(LocalFailure),
    /// A secret-free provider failure.
    Provider(ProviderFailure),
    /// A caller-owned resource bound was exhausted.
    Exhausted(ResourceExhaustion),
}

impl AlertFailure {
    /// Converts only alerts in the failure class.
    #[must_use]
    pub const fn from_alert(alert: Alert) -> Option<Self> {
        if matches!(alert.class(), AlertClass::Error) {
            Some(Self(alert))
        } else {
            None
        }
    }

    /// Returns the underlying assigned alert.
    #[must_use]
    pub const fn alert(self) -> Alert {
        self.0
    }
}
