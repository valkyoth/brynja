//! Bounded `no_std` protocol domains for Brynja.
//!
//! The package deliberately contains only protocol-neutral, allocation-free
//! value domains. It does not implement a TLS state machine or cryptography.

#![no_std]

pub mod alert;
pub mod arena_domain;
pub mod backend;
pub mod backend_dispatch;
mod backend_execution;
mod backend_instance;
mod backend_kat;
pub mod backend_session;
pub mod budget;
pub mod close;
pub mod constant_time;
pub mod error;
pub mod exhaustion;
pub mod numeric;
pub mod provider;
pub mod provider_capability;
pub mod provider_contract;
pub mod provider_request;
pub mod quantity;
pub mod read;
pub mod secret;
pub mod secret_destruction;
pub mod secret_memory;
mod secret_memory_volatile;
pub mod sequence;
pub mod version;
pub mod workspace;
pub mod write;

#[cfg(test)]
mod backend_security_tests;
#[cfg(test)]
mod backend_session_tests;

pub use alert::{
    Alert, AlertClass, AlertCode, AlertCodeClass, AlertDescription, AlertOrigin, AlertSeverity,
};
pub use arena_domain::{
    ArenaDomain, ArenaKind, CertificateDomain, OutputDomain, PlaintextDomain, SecretDomain,
    TranscriptDomain,
};
pub use backend::{
    BackendCandidate, BackendClass, BackendEvidenceOrigin, BackendFeature, BackendFeatureError,
    BackendFeatures, BackendFeaturesBuilder, BackendGenerationError, BackendIdentity,
    BackendPolicy, BackendProfile, BackendProfileError, BackendRuntimeGeneration,
};
pub use backend_dispatch::{
    ActiveBackend, BackendDispatch, BackendDispatchError, BackendFallbackReason,
    BackendSelectionReason, BackendSelectionReport, select_backend,
};
pub use backend_execution::{
    BackendCpuContext, BackendCpuIdentity, BackendCpuLease, BackendCpuRevalidationError,
    BackendKernelPermit,
};
pub use backend_instance::{BackendFeatureEvidence, BackendInstanceIdentity};
pub use backend_kat::{BackendKatFailure, BackendKatPass};
pub use backend_session::{
    BackendFault, BackendHealthSnapshot, BackendHealthState, BackendInitialization,
    BackendInitializationError, BackendServiceApproval, BackendSession, BackendSessionError,
};
pub use budget::{
    BudgetBuildError, ResourceBudget, ResourceBudgetBuilder, ResourceDomain, WorkBudget,
};
pub use close::{Cancellation, CloseOutcome};
pub use constant_time::{
    Choice, ConditionalSelect, ConditionalSwap, ConstantTimeEq, CtMask, compiler_barrier,
};
pub use error::{AlertFailure, FailureKind, LocalFailure, TlsFailure};
pub use exhaustion::{ExhaustionPhase, ResourceExhaustion, ResourceKind};
pub use numeric::{BoundedU64, BoundedUsize, NumericError};
pub use provider::{ProviderFailure, ProviderFailureKind, ProviderOperation};
pub use provider_capability::{
    ProviderCapabilities, ProviderCapabilitiesBuilder, ProviderCapabilityError,
};
pub use provider_contract::{
    InstalledProvider, ProviderAuthorization, ProviderAuthorizationError, ProviderHandle,
    ProviderInstallation, ProviderInstallationError, ProviderInstallationField,
};
pub use provider_request::{ProviderFrame, ProviderRequest, ProviderRequestError};
pub use quantity::{Count, Length};
pub use read::{ReadCursor, ReadError};
pub use secret::{
    InitializationTransition, ReplacementTransition, SecretContractError, SecretInitialization,
    SecretLifecycleContract, SecretState,
};
pub use secret_destruction::{
    DestructionCause, DestructionComplete, DestructionFailure, DestructionFailureKind,
    DestructionOutcome, DestructionTarget, DestructionTargets, SecretDestructor,
    TargetDestructionStatus,
};
pub use secret_memory::{
    OwnedRegionClearComplete, OwnedSecretRegion, SecretMemoryError, SecretRegionInitialization,
    clear_owned_region,
};
pub use sequence::{Epoch, SequenceNumber};
pub use version::{ProtocolFamily, ProtocolVersion};
pub use workspace::{
    Arena, ArenaError, Workspace, WorkspaceArenas, WorkspaceError, WorkspaceLayout,
    WorkspaceLayoutBuilder,
};
pub use write::{WriteCursor, WriteError};

/// Whether this package provides its complete planned protocol implementation.
///
/// This remains `false`; individual completed foundation domains have explicit
/// flags below.
pub const IMPLEMENTED: bool = false;

/// Whether the v0.5 failure and alert value domains are implemented.
pub const FAILURE_DOMAINS_IMPLEMENTED: bool = true;

/// Whether the v0.6 bounded numeric and immutable budget domains are implemented.
pub const BOUNDED_DOMAINS_IMPLEMENTED: bool = true;

/// Whether the v0.7 transactional borrowed read cursor is implemented.
pub const READ_CURSOR_IMPLEMENTED: bool = true;

/// Whether the v0.8 transactional caller-buffer write cursor is implemented.
pub const WRITE_CURSOR_IMPLEMENTED: bool = true;

/// Whether the v0.9 exact caller-owned workspace and arena model is implemented.
pub const WORKSPACE_ARENAS_IMPLEMENTED: bool = true;

/// Whether the v0.10 abstract secret-lifetime contract is implemented.
pub const SECRET_LIFETIME_CONTRACT_IMPLEMENTED: bool = true;

/// Whether the v0.11 owned-memory zeroization primitive is implemented.
pub const OWNED_MEMORY_ZEROIZATION_IMPLEMENTED: bool = true;

/// Whether the v0.12 constant-time foundation is implemented.
pub const CONSTANT_TIME_FOUNDATION_IMPLEMENTED: bool = true;

/// Whether the v0.13 provider capability and opaque-handle contracts are implemented.
pub const PROVIDER_CONTRACTS_IMPLEMENTED: bool = true;

/// Whether the v0.13.1 CPU backend capability and dispatch contract is implemented.
pub const CPU_BACKEND_CONTRACT_IMPLEMENTED: bool = true;

#[cfg(test)]
mod tests {
    #[test]
    fn package_claims_only_completed_foundation_domains() {
        assert!(!::core::hint::black_box(super::IMPLEMENTED));
        assert!(::core::hint::black_box(super::FAILURE_DOMAINS_IMPLEMENTED));
        assert!(::core::hint::black_box(super::BOUNDED_DOMAINS_IMPLEMENTED));
        assert!(::core::hint::black_box(super::READ_CURSOR_IMPLEMENTED));
        assert!(::core::hint::black_box(super::WRITE_CURSOR_IMPLEMENTED));
        assert!(::core::hint::black_box(super::WORKSPACE_ARENAS_IMPLEMENTED));
        assert!(::core::hint::black_box(
            super::SECRET_LIFETIME_CONTRACT_IMPLEMENTED
        ));
        assert!(::core::hint::black_box(
            super::OWNED_MEMORY_ZEROIZATION_IMPLEMENTED
        ));
        assert!(::core::hint::black_box(
            super::CONSTANT_TIME_FOUNDATION_IMPLEMENTED
        ));
        assert!(::core::hint::black_box(
            super::PROVIDER_CONTRACTS_IMPLEMENTED
        ));
        assert!(::core::hint::black_box(
            super::CPU_BACKEND_CONTRACT_IMPLEMENTED
        ));
    }
}
