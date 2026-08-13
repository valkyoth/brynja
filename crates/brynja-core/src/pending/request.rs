//! Typed admission of provider requests into the pending lifecycle.

use crate::{
    DestructionTarget, DestructionTargets, ProviderFrame, ProviderOperation, ProviderRequest,
    ProviderRequestError, ResourceBudget,
};

/// The exact asynchronous boundary requested by protocol code.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum PendingRequestKind {
    /// A certificate-chain operation.
    Certificate,
    /// A signature operation backed by an external key.
    Signature,
    /// A cryptographic operation delegated to an accelerator.
    Accelerator,
}

/// The provider-owned resource whose terminal cleanup is authoritative.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum PendingResource {
    /// Provider continuation state without an external secret handle.
    CertificateState,
    /// An external signing-key operation and its provider state.
    ExternalKey,
    /// An accelerator or opaque device handle and its provider state.
    AcceleratorHandle,
}

/// A caller-selected bound for resumptions and backpressure responses.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct PendingLimits {
    effect_attempts: u64,
    backpressure_responses: u64,
}

impl PendingLimits {
    /// Constructs nonzero immutable pending-operation limits.
    pub const fn new(
        effect_attempts: u64,
        backpressure_responses: u64,
    ) -> Result<Self, PendingLimitError> {
        if effect_attempts == 0 {
            Err(PendingLimitError::ZeroEffectAttempts)
        } else if backpressure_responses == 0 {
            Err(PendingLimitError::ZeroBackpressureResponses)
        } else {
            Ok(Self {
                effect_attempts,
                backpressure_responses,
            })
        }
    }

    /// Returns the maximum number of begin, resume, or cancellation calls.
    #[must_use]
    pub const fn effect_attempts(self) -> u64 {
        self.effect_attempts
    }

    /// Returns the maximum cumulative number of backpressure responses.
    #[must_use]
    pub const fn backpressure_responses(self) -> u64 {
        self.backpressure_responses
    }
}

/// Invalid pending-operation limits.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum PendingLimitError {
    /// No provider transition would be permitted.
    ZeroEffectAttempts,
    /// No backpressure response could be represented.
    ZeroBackpressureResponses,
}

/// A closed pending-request admission failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum PendingRequestError {
    /// The provider request does not match the requested pending boundary.
    WrongOperation(ProviderOperation),
    /// Poll or cancellation capability is absent on the exact provider.
    MissingCapability(ProviderOperation),
    /// The provider did not declare a mandatory destruction location.
    MissingDestructionTarget(DestructionTarget),
}

/// An affine provider request admitted to one exact pending boundary.
///
/// The value cannot be cloned, copied, formatted, or converted to a native
/// provider identifier. A retry or backpressure result returns this same value.
///
/// ```compile_fail
/// use brynja_core::PendingRequest;
///
/// fn duplicate(request: PendingRequest<'_, '_>) {
///     let _copy = request.clone();
/// }
/// ```
#[must_use = "a pending request must begin, retry, or be explicitly discarded"]
pub struct PendingRequest<'provider, 'data> {
    request: ProviderRequest<'provider, 'data>,
    kind: PendingRequestKind,
    resource: PendingResource,
    limits: PendingLimits,
    attempts: u64,
    backpressure: u64,
}

impl<'provider, 'data> PendingRequest<'provider, 'data> {
    /// Admits exactly one certificate-chain request.
    pub fn certificate(
        request: ProviderRequest<'provider, 'data>,
        limits: PendingLimits,
    ) -> Result<Self, PendingRequestError> {
        Self::admit(
            request,
            limits,
            PendingRequestKind::Certificate,
            PendingResource::CertificateState,
        )
    }

    /// Admits exactly one external-key signature request.
    pub fn signature(
        request: ProviderRequest<'provider, 'data>,
        limits: PendingLimits,
    ) -> Result<Self, PendingRequestError> {
        Self::admit(
            request,
            limits,
            PendingRequestKind::Signature,
            PendingResource::ExternalKey,
        )
    }

    /// Admits one accelerator-eligible cryptographic request.
    pub fn accelerator(
        request: ProviderRequest<'provider, 'data>,
        limits: PendingLimits,
    ) -> Result<Self, PendingRequestError> {
        Self::admit(
            request,
            limits,
            PendingRequestKind::Accelerator,
            PendingResource::AcceleratorHandle,
        )
    }

    fn admit(
        request: ProviderRequest<'provider, 'data>,
        limits: PendingLimits,
        kind: PendingRequestKind,
        resource: PendingResource,
    ) -> Result<Self, PendingRequestError> {
        let operation = request.operation();
        let valid = match kind {
            PendingRequestKind::Certificate => operation == ProviderOperation::CertificatePath,
            PendingRequestKind::Signature => operation == ProviderOperation::Sign,
            PendingRequestKind::Accelerator => operation.is_acceleratable(),
        };
        if !valid {
            return Err(PendingRequestError::WrongOperation(operation));
        }
        let provider = request.provider();
        for capability in [
            ProviderOperation::PendingPoll,
            ProviderOperation::PendingCancel,
        ] {
            if !provider.capabilities().contains(capability) {
                return Err(PendingRequestError::MissingCapability(capability));
            }
        }
        let required_target = match resource {
            PendingResource::ExternalKey => Some(DestructionTarget::ExternalStore),
            PendingResource::AcceleratorHandle => Some(DestructionTarget::Accelerator),
            PendingResource::CertificateState => None,
        };
        if let Some(target) = required_target
            && !provider.destruction_targets().contains(target)
        {
            return Err(PendingRequestError::MissingDestructionTarget(target));
        }
        Ok(Self {
            request,
            kind,
            resource,
            limits,
            attempts: 0,
            backpressure: 0,
        })
    }

    /// Returns the exact admitted pending boundary.
    #[must_use]
    pub const fn kind(&self) -> PendingRequestKind {
        self.kind
    }

    /// Returns the resource requiring terminal cleanup.
    #[must_use]
    pub const fn resource(&self) -> PendingResource {
        self.resource
    }

    /// Returns the exact original provider operation.
    #[must_use]
    pub const fn operation(&self) -> ProviderOperation {
        self.request.operation()
    }

    /// Returns the immutable version-neutral request frame.
    #[must_use]
    pub const fn frame(&self) -> &ProviderFrame<'data> {
        self.request.frame()
    }

    /// Returns the frozen caller resource budget.
    #[must_use]
    pub const fn resources(&self) -> ResourceBudget {
        self.request.resources()
    }

    /// Returns the remaining provider work allowance.
    #[must_use]
    pub const fn remaining_work(&self) -> u64 {
        self.request.remaining_work()
    }

    /// Charges work before an expensive provider step.
    pub const fn charge_work(&mut self, units: u64) -> Result<(), ProviderRequestError> {
        self.request.charge_work(units)
    }

    pub(crate) const fn limits(&self) -> PendingLimits {
        self.limits
    }

    pub(crate) fn begin_attempt(&mut self) -> bool {
        let Some(next) = self.attempts.checked_add(1) else {
            return false;
        };
        if next > self.limits.effect_attempts() {
            false
        } else {
            self.attempts = next;
            true
        }
    }

    pub(crate) fn record_backpressure(&mut self) -> bool {
        let Some(next) = self.backpressure.checked_add(1) else {
            return false;
        };
        if next > self.limits.backpressure_responses() {
            false
        } else {
            self.backpressure = next;
            true
        }
    }

    pub(crate) const fn attempts(&self) -> u64 {
        self.attempts
    }

    pub(crate) const fn backpressure(&self) -> u64 {
        self.backpressure
    }

    pub(crate) const fn destruction_targets(&self) -> DestructionTargets {
        self.request.provider().destruction_targets()
    }
}
