//! Downstream pending-provider effect and cleanup boundary.

use crate::{
    DestructionTargets, ProviderFailureKind, ProviderFrame, ProviderHandle, ProviderOperation,
};

use super::{PendingRequestKind, PendingResource};

/// Secret-free reason that an operation may be retried.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum PendingRetryReason {
    /// The provider has not yet made progress.
    NotReady,
    /// A transient provider condition prevented progress.
    TransientFailure,
    /// Cancellation was observed but is not yet durable.
    CancellationInProgress,
}

/// Secret-free backpressure classification.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum PendingBackpressure {
    /// The provider's bounded queue is full.
    QueueFull,
    /// The caller must drain output before retrying.
    OutputBlocked,
    /// The accelerator cannot currently accept work.
    DeviceBusy,
}

/// Immutable metadata presented to a downstream provider effect.
pub struct PendingEffectRequest<'request, 'data> {
    kind: PendingRequestKind,
    operation: ProviderOperation,
    frame: &'request ProviderFrame<'data>,
    attempt: u64,
    remaining_work: u64,
}

impl<'request, 'data> PendingEffectRequest<'request, 'data> {
    pub(crate) const fn new(
        kind: PendingRequestKind,
        operation: ProviderOperation,
        frame: &'request ProviderFrame<'data>,
        attempt: u64,
        remaining_work: u64,
    ) -> Self {
        Self {
            kind,
            operation,
            frame,
            attempt,
            remaining_work,
        }
    }

    /// Returns the exact pending request kind.
    #[must_use]
    pub const fn kind(&self) -> PendingRequestKind {
        self.kind
    }

    /// Returns the exact original provider operation.
    #[must_use]
    pub const fn operation(&self) -> ProviderOperation {
        self.operation
    }

    /// Returns the immutable version-neutral frame.
    #[must_use]
    pub const fn frame(&self) -> &ProviderFrame<'data> {
        self.frame
    }

    /// Returns the one-based effect attempt number.
    #[must_use]
    pub const fn attempt(&self) -> u64 {
        self.attempt
    }

    /// Returns the remaining precharged work allowance.
    #[must_use]
    pub const fn remaining_work(&self) -> u64 {
        self.remaining_work
    }
}

/// Non-forgeable authority for one provider-derived unit charge.
///
/// The lifecycle creates this value only after the provider has derived a
/// bounded cost and the authoritative request meter has accepted that cost.
///
/// ```compile_fail
/// use brynja_core::PendingWorkPermit;
///
/// fn forge() {
///     let _ = PendingWorkPermit { units: 1 };
/// }
/// ```
#[must_use = "charged work authority must be consumed by its provider step"]
pub struct PendingWorkPermit {
    units: u64,
}

impl PendingWorkPermit {
    pub(crate) const fn new(units: u64) -> Self {
        Self { units }
    }

    /// Returns the exact provider-derived units charged before this step.
    #[must_use]
    pub const fn units(&self) -> u64 {
        self.units
    }
}

/// One activation transition over lifecycle-owned prepared state.
#[must_use = "begin steps must be consumed by the lifecycle"]
pub enum PendingBeginStep {
    /// Provider continuation state became active.
    Active,
    /// No external resource remains active; retry the original request.
    Retry(PendingRetryReason),
    /// No external resource remains active; bounded backpressure was reported.
    Backpressure(PendingBackpressure),
    /// Activation failed and prepared state must be destroyed.
    Failed(ProviderFailureKind),
}

/// One resumable provider transition over lifecycle-owned state.
#[must_use = "pending steps must be consumed by the lifecycle"]
pub enum PendingStep {
    /// Work completed; the borrowed provider state must now be destroyed.
    Complete,
    /// Work made progress and remains pending.
    Active,
    /// Work remains retryable.
    Retry(PendingRetryReason),
    /// Work remains pending behind explicit backpressure.
    Backpressure(PendingBackpressure),
    /// Work failed; the borrowed provider state must now be destroyed.
    Failed(ProviderFailureKind),
}

/// One cancellation transition over lifecycle-owned state.
#[must_use = "cancellation steps must be consumed by the lifecycle"]
pub enum PendingCancelStep {
    /// Cancellation is durable; provider state must now be destroyed.
    Canceled,
    /// Cancellation must be retried.
    Retry(PendingRetryReason),
    /// Cancellation is subject to explicit backpressure.
    Backpressure(PendingBackpressure),
    /// Cancellation failed; provider state must now be destroyed.
    Failed(ProviderFailureKind),
}

/// Why pending provider state must be destroyed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum PendingDestructionCause {
    /// Prepared state is being closed after activation did not remain active.
    Activation,
    /// Provider work completed.
    Completion,
    /// Cancellation became durable.
    Cancellation,
    /// A provider transition failed.
    ProviderFailure,
    /// A caller-selected transition limit was exhausted.
    Exhaustion,
    /// The affine pending operation left scope.
    Drop,
}

/// A single-consumption authority to finish provider-state destruction.
///
/// An effect can only produce a completion or failure by consuming this token.
/// Informational events cannot authorize the lifecycle transition.
///
/// ```compile_fail
/// use brynja_core::PendingDestructionToken;
///
/// fn claim_twice(token: PendingDestructionToken) {
///     let _first = token.complete();
///     let _second = token.complete();
/// }
/// ```
#[must_use = "pending destruction authority must be consumed exactly once"]
pub struct PendingDestructionToken {
    resource: PendingResource,
    targets: DestructionTargets,
    cause: PendingDestructionCause,
}

impl PendingDestructionToken {
    pub(crate) const fn new(
        resource: PendingResource,
        targets: DestructionTargets,
        cause: PendingDestructionCause,
    ) -> Self {
        Self {
            resource,
            targets,
            cause,
        }
    }

    /// Returns the provider-owned resource covered by the transition.
    #[must_use]
    pub const fn resource(&self) -> PendingResource {
        self.resource
    }

    /// Returns all frozen local, external, accelerator, cache, and DMA duties.
    #[must_use]
    pub const fn targets(&self) -> DestructionTargets {
        self.targets
    }

    /// Returns why destruction is mandatory.
    #[must_use]
    pub const fn cause(&self) -> PendingDestructionCause {
        self.cause
    }

    /// Asserts that every applicable duty completed synchronously.
    pub const fn complete(self) -> PendingDestructionOutcome {
        PendingDestructionOutcome::Complete(PendingDestructionComplete {
            resource: self.resource,
            cause: self.cause,
        })
    }

    /// Consumes the authority into a terminal closed failure.
    pub const fn fail(self, kind: PendingDestructionFailureKind) -> PendingDestructionOutcome {
        PendingDestructionOutcome::Failed(PendingDestructionFailure {
            resource: self.resource,
            cause: self.cause,
            kind,
        })
    }
}

/// Proof that provider-state destruction completed.
#[must_use = "destruction completion must govern the terminal transition"]
pub struct PendingDestructionComplete {
    resource: PendingResource,
    cause: PendingDestructionCause,
}

impl PendingDestructionComplete {
    /// Returns the destroyed provider-owned resource.
    #[must_use]
    pub const fn resource(&self) -> PendingResource {
        self.resource
    }

    /// Returns the terminal transition cause.
    #[must_use]
    pub const fn cause(&self) -> PendingDestructionCause {
        self.cause
    }
}

/// Closed provider-state destruction failure class.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum PendingDestructionFailureKind {
    /// An external key could not be synchronously released or destroyed.
    ExternalKey,
    /// An accelerator handle or device state could not be destroyed.
    AcceleratorHandle,
    /// Cache or DMA completion could not be established.
    CacheOrDma,
    /// Other provider continuation state could not be destroyed.
    ProviderState,
}

/// Terminal secret-free failure of mandatory provider-state destruction.
#[must_use = "pending destruction failure is terminal"]
pub struct PendingDestructionFailure {
    resource: PendingResource,
    cause: PendingDestructionCause,
    kind: PendingDestructionFailureKind,
}

impl PendingDestructionFailure {
    /// Returns the provider resource that remains unaccounted for.
    #[must_use]
    pub const fn resource(&self) -> PendingResource {
        self.resource
    }

    /// Returns the terminal transition cause.
    #[must_use]
    pub const fn cause(&self) -> PendingDestructionCause {
        self.cause
    }

    /// Returns the closed failure category.
    #[must_use]
    pub const fn kind(&self) -> PendingDestructionFailureKind {
        self.kind
    }
}

/// Mandatory outcome of consuming destruction authority.
#[must_use = "pending destruction outcome must be handled"]
pub enum PendingDestructionOutcome {
    /// Every declared destruction duty completed.
    Complete(PendingDestructionComplete),
    /// Destruction failed and the lifecycle is terminal.
    Failed(PendingDestructionFailure),
}

/// Downstream effect boundary for one provider's pending continuation state.
///
/// `provider_handle` is an immutable identity assertion for this effect and
/// must never change during its borrow. State preparation and cost methods must
/// be bounded and effect-free: prepared state is inert local cleanup metadata.
/// Activation, resume, cancellation, and destruction mutate state already
/// owned by the lifecycle, so unwinding cannot move it beyond [`Drop`]. A
/// retry or backpressure step asserts that activation left no external
/// resource active, but the lifecycle still destroys prepared state before
/// returning the request.
pub trait PendingProvider {
    /// Opaque provider-owned continuation state.
    type State;

    /// Returns the exact installed provider implemented by this effect.
    fn provider_handle(&self) -> ProviderHandle<'_>;

    /// Creates only inert local state without an external or platform effect.
    ///
    /// The returned value must describe partially initialized cleanup safely
    /// before activation can create an external resource.
    fn prepare_state(
        &self,
        request: &PendingEffectRequest<'_, '_>,
    ) -> Result<Self::State, ProviderFailureKind>;

    /// Derives the bounded, effect-free charge for creating state.
    fn begin_cost(
        &self,
        request: &PendingEffectRequest<'_, '_>,
    ) -> Result<u64, ProviderFailureKind>;

    /// Activates lifecycle-owned state after its exact charge was accepted.
    fn begin(
        &mut self,
        state: &mut Self::State,
        request: PendingEffectRequest<'_, '_>,
        permit: PendingWorkPermit,
    ) -> PendingBeginStep;

    /// Derives the bounded, effect-free charge for one resume transition.
    fn resume_cost(
        &self,
        state: &Self::State,
        request: &PendingEffectRequest<'_, '_>,
    ) -> Result<u64, ProviderFailureKind>;

    /// Performs one bounded, precharged resume transition.
    fn resume(
        &mut self,
        state: &mut Self::State,
        request: PendingEffectRequest<'_, '_>,
        permit: PendingWorkPermit,
    ) -> PendingStep;

    /// Derives the bounded, effect-free charge for one cancellation attempt.
    fn cancel_cost(
        &self,
        state: &Self::State,
        request: &PendingEffectRequest<'_, '_>,
    ) -> Result<u64, ProviderFailureKind>;

    /// Requests durable cancellation after its exact charge was accepted.
    fn cancel(
        &mut self,
        state: &mut Self::State,
        request: PendingEffectRequest<'_, '_>,
        permit: PendingWorkPermit,
    ) -> PendingCancelStep;

    /// Destroys borrowed continuation state and consumes exact authority.
    ///
    /// Borrowed ownership ensures an unwind leaves state available to the
    /// lifecycle's `Drop` handling for another mandatory cleanup attempt.
    fn destroy(
        &mut self,
        state: &mut Self::State,
        token: PendingDestructionToken,
    ) -> PendingDestructionOutcome;

    /// Makes a destruction failure reached through `Drop` durable or fail-stop.
    fn handle_drop_failure(&mut self, failure: PendingDestructionFailure);
}
