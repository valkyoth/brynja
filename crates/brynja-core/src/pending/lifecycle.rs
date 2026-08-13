//! Failure-atomic ownership of one pending provider operation.

use crate::{ProviderFailureKind, ProviderOperation};

use super::{
    PendingBackpressure, PendingBegin, PendingCancelStep, PendingDestructionCause,
    PendingDestructionFailure, PendingDestructionFailureKind, PendingDestructionOutcome,
    PendingDestructionToken, PendingEffectRequest, PendingProvider, PendingRequest,
    PendingRequestKind, PendingResource, PendingRetryReason, PendingStep,
};

/// A terminal pending-operation failure class.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum PendingFailureKind {
    /// The downstream provider rejected or failed the effect.
    Provider(ProviderFailureKind),
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
    kind: PendingFailureKind,
    request_kind: PendingRequestKind,
    operation: ProviderOperation,
    resource: PendingResource,
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
    request_kind: PendingRequestKind,
    operation: ProviderOperation,
    resource: PendingResource,
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
    request_kind: PendingRequestKind,
    operation: ProviderOperation,
    resource: PendingResource,
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

/// Affine ownership of one exact pending provider operation.
///
/// Dropping an active value synchronously destroys its provider state and
/// routes any failure through [`PendingProvider::handle_drop_failure`].
///
/// ```compile_fail
/// use brynja_core::PendingOperation;
///
/// fn duplicate<Effect: brynja_core::PendingProvider>(
///     operation: PendingOperation<'_, '_, '_, Effect>,
/// ) {
///     let _copy = operation.clone();
/// }
/// ```
#[must_use = "pending provider state must be resumed, canceled, or dropped"]
pub struct PendingOperation<'provider, 'data, 'effect, Effect: PendingProvider> {
    request: PendingRequest<'provider, 'data>,
    state: Option<Effect::State>,
    effect: &'effect mut Effect,
    attempts: u64,
    backpressure: u64,
}

impl<'provider, 'data, 'effect, Effect: PendingProvider>
    PendingOperation<'provider, 'data, 'effect, Effect>
{
    /// Begins one pending operation without implicit provider fallback.
    pub fn begin(
        mut request: PendingRequest<'provider, 'data>,
        effect: &'effect mut Effect,
    ) -> PendingStart<'provider, 'data, 'effect, Effect> {
        if !request.begin_attempt() {
            return PendingStart::Failed(failure_from_request(
                &request,
                PendingFailureKind::EffectAttemptsExhausted,
            ));
        }
        let effect_request = PendingEffectRequest::new(
            request.kind(),
            request.operation(),
            request.frame(),
            request.attempts(),
            request.remaining_work(),
        );
        match effect.begin(effect_request) {
            PendingBegin::Active(state) => {
                let attempts = request.attempts();
                let backpressure = request.backpressure();
                PendingStart::Active(Self {
                    request,
                    state: Some(state),
                    effect,
                    attempts,
                    backpressure,
                })
            }
            PendingBegin::Retry(reason) => PendingStart::Retry(request, reason),
            PendingBegin::Backpressure(reason) => {
                if request.record_backpressure() {
                    PendingStart::Backpressure(request, reason)
                } else {
                    PendingStart::Failed(failure_from_request(
                        &request,
                        PendingFailureKind::BackpressureExhausted,
                    ))
                }
            }
            PendingBegin::Failed(kind) => PendingStart::Failed(failure_from_request(
                &request,
                PendingFailureKind::Provider(kind),
            )),
        }
    }

    /// Returns the exact pending boundary.
    #[must_use]
    pub const fn request_kind(&self) -> PendingRequestKind {
        self.request.kind()
    }

    /// Returns the exact original provider operation.
    #[must_use]
    pub const fn operation(&self) -> ProviderOperation {
        self.request.operation()
    }

    /// Returns the number of effect transitions already attempted.
    #[must_use]
    pub const fn attempts(&self) -> u64 {
        self.attempts
    }

    /// Returns the cumulative number of backpressure responses.
    #[must_use]
    pub const fn backpressure_responses(&self) -> u64 {
        self.backpressure
    }

    /// Charges work before the next expensive provider transition.
    pub const fn charge_work(&mut self, units: u64) -> Result<(), crate::ProviderRequestError> {
        self.request.charge_work(units)
    }

    /// Performs one bounded resume transition.
    pub fn resume(mut self) -> PendingTransition<'provider, 'data, 'effect, Effect> {
        if !self.begin_attempt() {
            return self.finish_failure(
                PendingFailureKind::EffectAttemptsExhausted,
                PendingDestructionCause::Exhaustion,
            );
        }
        let Some(state) = self.state.take() else {
            return self.invariant_failure();
        };
        let request = PendingEffectRequest::new(
            self.request.kind(),
            self.request.operation(),
            self.request.frame(),
            self.attempts,
            self.request.remaining_work(),
        );
        match self.effect.resume(state, request) {
            PendingStep::Complete(state) => {
                self.state = Some(state);
                self.finish_complete()
            }
            PendingStep::Active(state) => {
                self.state = Some(state);
                PendingTransition::Active(self)
            }
            PendingStep::Retry(state, reason) => {
                self.state = Some(state);
                PendingTransition::Retry(self, reason)
            }
            PendingStep::Backpressure(state, reason) => {
                self.state = Some(state);
                self.record_backpressure(reason)
            }
            PendingStep::Failed(state, kind) => {
                self.state = Some(state);
                self.finish_failure(
                    PendingFailureKind::Provider(kind),
                    PendingDestructionCause::ProviderFailure,
                )
            }
        }
    }

    /// Requests cancellation and retains ownership until it is durable.
    pub fn cancel(mut self) -> PendingTransition<'provider, 'data, 'effect, Effect> {
        if !self.begin_attempt() {
            return self.finish_failure(
                PendingFailureKind::EffectAttemptsExhausted,
                PendingDestructionCause::Exhaustion,
            );
        }
        let Some(state) = self.state.take() else {
            return self.invariant_failure();
        };
        let request = PendingEffectRequest::new(
            self.request.kind(),
            self.request.operation(),
            self.request.frame(),
            self.attempts,
            self.request.remaining_work(),
        );
        match self.effect.cancel(state, request) {
            PendingCancelStep::Canceled(state) => {
                self.state = Some(state);
                self.finish_canceled()
            }
            PendingCancelStep::Retry(state, reason) => {
                self.state = Some(state);
                PendingTransition::Retry(self, reason)
            }
            PendingCancelStep::Backpressure(state, reason) => {
                self.state = Some(state);
                self.record_backpressure(reason)
            }
            PendingCancelStep::Failed(state, kind) => {
                self.state = Some(state);
                self.finish_failure(
                    PendingFailureKind::Provider(kind),
                    PendingDestructionCause::ProviderFailure,
                )
            }
        }
    }

    fn begin_attempt(&mut self) -> bool {
        let Some(next) = self.attempts.checked_add(1) else {
            return false;
        };
        if next > self.request.limits().effect_attempts() {
            false
        } else {
            self.attempts = next;
            true
        }
    }

    fn record_backpressure(
        mut self,
        reason: PendingBackpressure,
    ) -> PendingTransition<'provider, 'data, 'effect, Effect> {
        let next = self.backpressure.checked_add(1);
        match next {
            Some(value) if value <= self.request.limits().backpressure_responses() => {
                self.backpressure = value;
                PendingTransition::Backpressure(self, reason)
            }
            Some(_) | None => self.finish_failure(
                PendingFailureKind::BackpressureExhausted,
                PendingDestructionCause::Exhaustion,
            ),
        }
    }

    fn finish_complete(mut self) -> PendingTransition<'provider, 'data, 'effect, Effect> {
        match self.destroy(PendingDestructionCause::Completion) {
            Ok(()) => PendingTransition::Complete(PendingCompletion {
                request_kind: self.request.kind(),
                operation: self.request.operation(),
                resource: self.request.resource(),
            }),
            Err(failure) => PendingTransition::Failed(self.destruction_failure(failure)),
        }
    }

    fn finish_canceled(mut self) -> PendingTransition<'provider, 'data, 'effect, Effect> {
        match self.destroy(PendingDestructionCause::Cancellation) {
            Ok(()) => PendingTransition::Canceled(PendingCancellation {
                request_kind: self.request.kind(),
                operation: self.request.operation(),
                resource: self.request.resource(),
            }),
            Err(failure) => PendingTransition::Failed(self.destruction_failure(failure)),
        }
    }

    fn finish_failure(
        mut self,
        kind: PendingFailureKind,
        cause: PendingDestructionCause,
    ) -> PendingTransition<'provider, 'data, 'effect, Effect> {
        match self.destroy(cause) {
            Ok(()) => PendingTransition::Failed(failure_from_request(&self.request, kind)),
            Err(failure) => PendingTransition::Failed(self.destruction_failure(failure)),
        }
    }

    fn invariant_failure(self) -> PendingTransition<'provider, 'data, 'effect, Effect> {
        PendingTransition::Failed(failure_from_request(
            &self.request,
            PendingFailureKind::Destruction(PendingDestructionFailureKind::ProviderState),
        ))
    }

    fn destroy(&mut self, cause: PendingDestructionCause) -> Result<(), PendingDestructionFailure> {
        let Some(state) = self.state.take() else {
            return Ok(());
        };
        let token = PendingDestructionToken::new(
            self.request.resource(),
            self.request.destruction_targets(),
            cause,
        );
        match self.effect.destroy(state, token) {
            PendingDestructionOutcome::Complete(_) => Ok(()),
            PendingDestructionOutcome::Failed(failure) => Err(failure),
        }
    }

    fn destruction_failure(&self, failure: PendingDestructionFailure) -> PendingFailure {
        failure_from_request(
            &self.request,
            PendingFailureKind::Destruction(failure.kind()),
        )
    }
}

impl<Effect: PendingProvider> Drop for PendingOperation<'_, '_, '_, Effect> {
    fn drop(&mut self) {
        if let Err(failure) = self.destroy(PendingDestructionCause::Drop) {
            self.effect.handle_drop_failure(failure);
        }
    }
}

fn failure_from_request(
    request: &PendingRequest<'_, '_>,
    kind: PendingFailureKind,
) -> PendingFailure {
    PendingFailure {
        kind,
        request_kind: request.kind(),
        operation: request.operation(),
        resource: request.resource(),
    }
}
