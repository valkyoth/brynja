//! Bounded `no_std` protocol domains for Brynja.
//!
//! The package deliberately contains only protocol-neutral, allocation-free
//! value domains. It does not implement a TLS state machine or cryptography.

#![no_std]

pub mod alert;
pub mod close;
pub mod error;
pub mod exhaustion;
pub mod provider;
pub mod version;

pub use alert::{Alert, AlertClass, AlertCode, AlertDescription, AlertOrigin, AlertSeverity};
pub use close::{Cancellation, CloseOutcome};
pub use error::{AlertFailure, LocalFailure, TlsFailure};
pub use exhaustion::{ExhaustionPhase, ResourceExhaustion, ResourceKind};
pub use provider::{ProviderFailure, ProviderFailureKind, ProviderOperation};
pub use version::{ProtocolFamily, ProtocolVersion};

/// Whether this package provides its planned implementation.
///
/// The foundation release intentionally reports `false`.
pub const IMPLEMENTED: bool = false;

/// Whether the v0.5 failure and alert value domains are implemented.
pub const FAILURE_DOMAINS_IMPLEMENTED: bool = true;

#[cfg(test)]
mod tests {
    #[test]
    fn foundation_does_not_claim_implementation() {
        assert!(!::core::hint::black_box(super::IMPLEMENTED));
        assert!(::core::hint::black_box(super::FAILURE_DOMAINS_IMPLEMENTED));
    }
}
