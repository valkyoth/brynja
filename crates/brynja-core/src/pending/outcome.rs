//! Secret-free outcomes of pending provider transitions.

use crate::{ProviderFailureKind, ProviderOperation};

use super::{
    PendingBackpressure, PendingDestructionFailureKind, PendingOperation, PendingProvider,
    PendingRequest, PendingRequestKind, PendingResource, PendingRetryReason,
};

/// A terminal pending-operation failure class.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum PendingFailureKind {
    /// The effect is not bound to the provider that authorized the request.
    ProviderMismatch,
    /// The downstream provider rejected or failed the effect.
    Provider(ProviderFailureKind),
    /// Provider-derived work exceeded the authoritative request meter.
    WorkExhausted,
    /// The provider proposed a zero-unit charge for an effectful transition.
    InvalidWorkCharge,
    /// The caller-selected resume bound was exhausted.
    EffectAttemptsExhausted,
    /// The caller-selected backpressure bound was exhausted.
    BackpressureExhausted,
    /// Mandatory provider-state destruction failed.
    Destruction(PendingDestructionFailureKind),
}

/// A terminal secret-free pending-operation failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[must_use = "pending operation failure is terminal"]
pub struct PendingFailure {
    pub(crate) kind: PendingFailureKind,
    pub(crate) request_kind: PendingRequestKind,
    pub(crate) operation: ProviderOperation,
    pub(crate) resource: PendingResource,
}

impl PendingFailure {
    /// Returns the terminal failure category.
    #[must_use]
    pub const fn kind(self) -> PendingFailureKind {
        self.kind
    }

    /// Returns the exact pending boundary that failed.
    #[must_use]
    pub const fn request_kind(self) -> PendingRequestKind {
        self.request_kind
    }

    /// Returns the original exact provider operation.
    #[must_use]
    pub const fn operation(self) -> ProviderOperation {
        self.operation
    }

    /// Returns the provider resource covered by terminal cleanup.
    #[must_use]
    pub const fn resource(self) -> PendingResource {
        self.resource
    }
}

/// Authoritative completion after provider state was destroyed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[must_use = "completion must govern the caller's next state"]
pub struct PendingCompletion {
    pub(crate) request_kind: PendingRequestKind,
    pub(crate) operation: ProviderOperation,
    pub(crate) resource: PendingResource,
}

impl PendingCompletion {
    /// Returns the completed pending boundary.
    #[must_use]
    pub const fn request_kind(self) -> PendingRequestKind {
        self.request_kind
    }

    /// Returns the completed provider operation.
    #[must_use]
    pub const fn operation(self) -> ProviderOperation {
        self.operation
    }

    /// Returns the resource whose cleanup completed.
    #[must_use]
    pub const fn resource(self) -> PendingResource {
        self.resource
    }
}

/// Authoritative cancellation after provider state was destroyed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[must_use = "cancellation must govern the caller's next state"]
pub struct PendingCancellation {
    pub(crate) request_kind: PendingRequestKind,
    pub(crate) operation: ProviderOperation,
    pub(crate) resource: PendingResource,
}

impl PendingCancellation {
    /// Returns the canceled pending boundary.
    #[must_use]
    pub const fn request_kind(self) -> PendingRequestKind {
        self.request_kind
    }

    /// Returns the canceled provider operation.
    #[must_use]
    pub const fn operation(self) -> ProviderOperation {
        self.operation
    }

    /// Returns the resource whose cleanup completed.
    #[must_use]
    pub const fn resource(self) -> PendingResource {
        self.resource
    }
}

/// Result of attempting to create provider continuation state.
#[must_use = "pending start ownership must be handled"]
pub enum PendingStart<'provider, 'data, 'effect, Effect: PendingProvider> {
    /// Provider continuation state is active.
    Active(PendingOperation<'provider, 'data, 'effect, Effect>),
    /// No state was created; the same request may be retried.
    Retry(PendingRequest<'provider, 'data>, PendingRetryReason),
    /// No state was created; the same request is backpressured.
    Backpressure(PendingRequest<'provider, 'data>, PendingBackpressure),
    /// No state was created and the request failed.
    Failed(PendingFailure),
}

/// Result of one resume or cancellation transition.
#[must_use = "pending transition must be handled"]
pub enum PendingTransition<'provider, 'data, 'effect, Effect: PendingProvider> {
    /// Work remains active after progress.
    Active(PendingOperation<'provider, 'data, 'effect, Effect>),
    /// Work remains active and may be retried.
    Retry(
        PendingOperation<'provider, 'data, 'effect, Effect>,
        PendingRetryReason,
    ),
    /// Work remains active behind bounded backpressure.
    Backpressure(
        PendingOperation<'provider, 'data, 'effect, Effect>,
        PendingBackpressure,
    ),
    /// Work and mandatory provider-state destruction completed.
    Complete(PendingCompletion),
    /// Cancellation and mandatory provider-state destruction completed.
    Canceled(PendingCancellation),
    /// The lifecycle is terminal.
    Failed(PendingFailure),
}
