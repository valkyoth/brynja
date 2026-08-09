//! Secret-destruction duties and completion outcomes.

/// Why a secret or partially initialized region became obsolete.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum DestructionCause {
    /// Initialization could not complete.
    InitializationFailure,
    /// The operation was explicitly canceled.
    Cancellation,
    /// A provider failed before commitment.
    ProviderFailure,
    /// A caller-owned resource or work budget was exhausted.
    Exhaustion,
    /// A live secret was replaced.
    Replacement,
    /// A live secret was explicitly made obsolete.
    Obsolete,
    /// An affine lifecycle value left scope.
    Drop,
}

/// One location whose copy of a secret must be destroyed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum DestructionTarget {
    /// The complete locally owned memory region.
    LocalMemory,
    /// A persistent or external secret store.
    ExternalStore,
    /// An accelerator or opaque device slot.
    Accelerator,
    /// A software- or device-managed cache copy.
    Cache,
    /// A DMA-visible or device-visible region.
    Dma,
}

/// The exact set of locations covered by one lifecycle contract.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct DestructionTargets {
    local_memory: bool,
    external_store: bool,
    accelerator: bool,
    cache: bool,
    dma: bool,
}

impl DestructionTargets {
    /// Describes every location explicitly.
    #[must_use]
    pub const fn new(
        local_memory: bool,
        external_store: bool,
        accelerator: bool,
        cache: bool,
        dma: bool,
    ) -> Self {
        Self {
            local_memory,
            external_store,
            accelerator,
            cache,
            dma,
        }
    }

    /// Describes a secret that exists only in locally owned memory.
    #[must_use]
    pub const fn local_memory() -> Self {
        Self::new(true, false, false, false, false)
    }

    /// Describes all five modeled locations.
    #[must_use]
    pub const fn all() -> Self {
        Self::new(true, true, true, true, true)
    }

    /// Returns whether one target is covered.
    #[must_use]
    pub const fn contains(self, target: DestructionTarget) -> bool {
        match target {
            DestructionTarget::LocalMemory => self.local_memory,
            DestructionTarget::ExternalStore => self.external_store,
            DestructionTarget::Accelerator => self.accelerator,
            DestructionTarget::Cache => self.cache,
            DestructionTarget::Dma => self.dma,
        }
    }

    pub(crate) const fn is_empty(self) -> bool {
        !self.local_memory && !self.external_store && !self.accelerator && !self.cache && !self.dma
    }
}

/// Result of performing one target-specific destruction duty.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum TargetDestructionStatus {
    /// The complete target-specific duty finished synchronously.
    Complete,
    /// The target could not establish complete destruction.
    Failed,
}

/// Caller- or provider-supplied destruction effects.
///
/// Returning [`TargetDestructionStatus::Complete`] is a security assertion:
/// the implementation has completed the full target-specific duty, including
/// required cache, device, or DMA completion. It is not an informational event.
/// Brynja v0.10 supplies no production local-memory implementation; the first
/// admitted implementation is gated by the v0.11 emitted-code review.
pub trait SecretDestructor {
    /// Performs one complete target-specific destruction duty.
    fn destroy(
        &mut self,
        target: DestructionTarget,
        cause: DestructionCause,
    ) -> TargetDestructionStatus;

    /// Handles a destruction failure that cannot be returned from `Drop`.
    ///
    /// The implementation must synchronously make the failure durable or
    /// initiate its platform-specific fail-stop response before returning.
    /// Examples cover latching permanent-error state, recording a bounded
    /// secret-free metric, resetting an embedded target, or aborting a hosted
    /// process. Returning is a security assertion that silent continuation is
    /// impossible under the caller's operating contract.
    fn handle_drop_failure(&mut self, failure: DestructionFailure);
}

/// A terminal destruction-failure category.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum DestructionFailureKind {
    /// A target-specific destruction effect failed.
    TargetFailed,
    /// Private lifecycle state was internally inconsistent.
    ContractInvariant,
}

/// A non-cloneable token proving every selected duty reported completion.
///
/// The token has no public constructor and does not implement formatting,
/// cloning, copying, or serialization. Consuming a lifecycle operation is the
/// only way to receive it.
#[must_use = "destruction completion must govern the next state transition"]
pub struct DestructionComplete {
    cause: DestructionCause,
}

impl DestructionComplete {
    /// Returns the transition that required destruction.
    #[must_use]
    pub const fn cause(&self) -> DestructionCause {
        self.cause
    }
}

/// A terminal, secret-free destruction failure.
///
/// This value is non-cloneable and non-formattable. It carries no secret,
/// length, offset, provider-native code, or arbitrary text.
#[must_use = "a destruction failure is terminal"]
pub struct DestructionFailure {
    cause: DestructionCause,
    kind: DestructionFailureKind,
    target: Option<DestructionTarget>,
}

impl DestructionFailure {
    /// Returns why destruction was required.
    #[must_use]
    pub const fn cause(&self) -> DestructionCause {
        self.cause
    }

    /// Returns the closed failure category.
    #[must_use]
    pub const fn kind(&self) -> DestructionFailureKind {
        self.kind
    }

    /// Returns the failed target when a target-specific effect failed.
    #[must_use]
    pub const fn target(&self) -> Option<DestructionTarget> {
        self.target
    }
}

/// Mandatory outcome of an explicit destruction transition.
#[must_use = "destruction outcomes must be handled"]
pub enum DestructionOutcome {
    /// Every selected duty completed exactly once.
    Complete(DestructionComplete),
    /// Destruction failed and the lifecycle is terminal.
    Failed(DestructionFailure),
}

fn attempt<D: SecretDestructor>(
    destructor: &mut D,
    targets: DestructionTargets,
    target: DestructionTarget,
    cause: DestructionCause,
    attempted: &mut bool,
    first_failure: &mut Option<DestructionTarget>,
) {
    if targets.contains(target) {
        *attempted = true;
        if matches!(
            destructor.destroy(target, cause),
            TargetDestructionStatus::Failed
        ) && first_failure.is_none()
        {
            *first_failure = Some(target);
        }
    }
}

pub(crate) fn run_destruction<D: SecretDestructor>(
    destructor: &mut D,
    targets: DestructionTargets,
    cause: DestructionCause,
) -> DestructionOutcome {
    let mut attempted = false;
    let mut first_failure = None;
    attempt(
        destructor,
        targets,
        DestructionTarget::LocalMemory,
        cause,
        &mut attempted,
        &mut first_failure,
    );
    attempt(
        destructor,
        targets,
        DestructionTarget::ExternalStore,
        cause,
        &mut attempted,
        &mut first_failure,
    );
    attempt(
        destructor,
        targets,
        DestructionTarget::Accelerator,
        cause,
        &mut attempted,
        &mut first_failure,
    );
    attempt(
        destructor,
        targets,
        DestructionTarget::Cache,
        cause,
        &mut attempted,
        &mut first_failure,
    );
    attempt(
        destructor,
        targets,
        DestructionTarget::Dma,
        cause,
        &mut attempted,
        &mut first_failure,
    );

    match first_failure {
        Some(target) => DestructionOutcome::Failed(DestructionFailure {
            cause,
            kind: DestructionFailureKind::TargetFailed,
            target: Some(target),
        }),
        None if attempted => DestructionOutcome::Complete(DestructionComplete { cause }),
        None => invariant_failure(cause),
    }
}

pub(crate) const fn invariant_failure(cause: DestructionCause) -> DestructionOutcome {
    DestructionOutcome::Failed(invariant_failure_value(cause))
}

pub(crate) const fn invariant_failure_value(cause: DestructionCause) -> DestructionFailure {
    DestructionFailure {
        cause,
        kind: DestructionFailureKind::ContractInvariant,
        target: None,
    }
}
