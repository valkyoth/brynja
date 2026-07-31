//! Non-secret TLS failure domains.
//!
//! Failure values do not carry arbitrary text, byte slices, provider-native
//! codes, cryptographic material, or formatting implementations.

use crate::{Alert, AlertClass, ProtocolVersion, ProviderFailure, ResourceExhaustion};

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

/// The cause category carried by a [`TlsFailure`].
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum FailureKind {
    /// A version-aware protocol alert failure.
    Alert(AlertFailure),
    /// A provider-independent local failure.
    Local(LocalFailure),
    /// A secret-free provider failure.
    Provider(ProviderFailure),
    /// A caller-owned resource bound was exhausted.
    Exhausted(ResourceExhaustion),
}

/// A protocol-version-aware TLS failure with no formatting surface.
///
/// Orderly close and explicit cancellation are deliberately not variants.
///
/// ```compile_fail
/// use brynja_core::{LocalFailure, TlsFailure};
/// let failure = TlsFailure::local(
///     brynja_core::ProtocolVersion::Tls13,
///     LocalFailure::InvalidInput,
/// );
/// let _ = format!("{failure:?}");
/// ```
///
/// ```compile_fail
/// use brynja_core::{LocalFailure, TlsFailure};
/// let secret = [7_u8; 32];
/// let _ = TlsFailure::local(
///     brynja_core::ProtocolVersion::Tls13,
///     LocalFailure::InvalidInput,
///     secret,
/// );
/// ```
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct TlsFailure {
    version: ProtocolVersion,
    kind: FailureKind,
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

impl TlsFailure {
    /// Constructs a protocol alert failure.
    #[must_use]
    pub const fn alert(failure: AlertFailure) -> Self {
        Self {
            version: failure.alert().version(),
            kind: FailureKind::Alert(failure),
        }
    }

    /// Constructs a local failure for a concrete protocol version.
    #[must_use]
    pub const fn local(version: ProtocolVersion, failure: LocalFailure) -> Self {
        Self {
            version,
            kind: FailureKind::Local(failure),
        }
    }

    /// Constructs a provider failure for a concrete protocol version.
    #[must_use]
    pub const fn provider(version: ProtocolVersion, failure: ProviderFailure) -> Self {
        Self {
            version,
            kind: FailureKind::Provider(failure),
        }
    }

    /// Constructs an exhaustion failure for a concrete protocol version.
    #[must_use]
    pub const fn exhausted(version: ProtocolVersion, failure: ResourceExhaustion) -> Self {
        Self {
            version,
            kind: FailureKind::Exhausted(failure),
        }
    }

    /// Returns the concrete protocol version.
    #[must_use]
    pub const fn version(self) -> ProtocolVersion {
        self.version
    }

    /// Returns the typed, non-secret failure category.
    #[must_use]
    pub const fn kind(self) -> FailureKind {
        self.kind
    }
}
