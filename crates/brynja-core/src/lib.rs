//! Bounded `no_std` protocol domains for Brynja.
//!
//! The package deliberately contains only protocol-neutral, allocation-free
//! value domains. It does not implement a TLS state machine or cryptography.

#![no_std]

pub mod alert;
pub mod budget;
pub mod close;
pub mod error;
pub mod exhaustion;
pub mod numeric;
pub mod provider;
pub mod quantity;
pub mod sequence;
pub mod version;

pub use alert::{
    Alert, AlertClass, AlertCode, AlertCodeClass, AlertDescription, AlertOrigin, AlertSeverity,
};
pub use budget::{
    BudgetBuildError, ResourceBudget, ResourceBudgetBuilder, ResourceDomain, WorkBudget,
};
pub use close::{Cancellation, CloseOutcome};
pub use error::{AlertFailure, FailureKind, LocalFailure, TlsFailure};
pub use exhaustion::{ExhaustionPhase, ResourceExhaustion, ResourceKind};
pub use numeric::{BoundedU64, BoundedUsize, NumericError};
pub use provider::{ProviderFailure, ProviderFailureKind, ProviderOperation};
pub use quantity::{Count, Length};
pub use sequence::{Epoch, SequenceNumber};
pub use version::{ProtocolFamily, ProtocolVersion};

/// Whether this package provides its planned implementation.
///
/// The foundation release intentionally reports `false`.
pub const IMPLEMENTED: bool = false;

/// Whether the v0.5 failure and alert value domains are implemented.
pub const FAILURE_DOMAINS_IMPLEMENTED: bool = true;

/// Whether the v0.6 bounded numeric and immutable budget domains are implemented.
pub const BOUNDED_DOMAINS_IMPLEMENTED: bool = true;

#[cfg(test)]
mod tests {
    #[test]
    fn foundation_does_not_claim_implementation() {
        assert!(!::core::hint::black_box(super::IMPLEMENTED));
        assert!(::core::hint::black_box(super::FAILURE_DOMAINS_IMPLEMENTED));
        assert!(::core::hint::black_box(super::BOUNDED_DOMAINS_IMPLEMENTED));
    }
}
