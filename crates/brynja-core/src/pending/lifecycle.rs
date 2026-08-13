//! Failure-atomic ownership of one pending provider operation.

use crate::ProviderOperation;

use super::{
    PendingBackpressure, PendingBegin, PendingCancelStep, PendingCancellation, PendingCompletion,
    PendingDestructionCause, PendingDestructionFailure, PendingDestructionFailureKind,
    PendingDestructionOutcome, PendingDestructionToken, PendingEffectRequest, PendingFailure,
    PendingFailureKind, PendingProvider, PendingRequest, PendingRequestKind, PendingStart,
    PendingStep, PendingTransition, PendingWorkPermit,
};

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
        if !request.is_bound_to(&effect.provider_handle()) {
            return PendingStart::Failed(failure_from_request(
                &request,
                PendingFailureKind::ProviderMismatch,
            ));
        }
        if !request.begin_attempt() {
            return PendingStart::Failed(failure_from_request(
                &request,
                PendingFailureKind::EffectAttemptsExhausted,
            ));
        }
        let cost_request = PendingEffectRequest::new(
            request.kind(),
            request.operation(),
            request.frame(),
            request.attempts(),
            request.remaining_work(),
        );
        let units = match effect.begin_cost(&cost_request) {
            Ok(units) => units,
            Err(kind) => {
                return PendingStart::Failed(failure_from_request(
                    &request,
                    PendingFailureKind::Provider(kind),
                ));
            }
        };
        if units == 0 {
            return PendingStart::Failed(failure_from_request(
                &request,
                PendingFailureKind::InvalidWorkCharge,
            ));
        }
        if !request.is_bound_to(&effect.provider_handle()) {
            return PendingStart::Failed(failure_from_request(
                &request,
                PendingFailureKind::ProviderMismatch,
            ));
        }
        if request.charge_work(units).is_err() {
            return PendingStart::Failed(failure_from_request(
                &request,
                PendingFailureKind::WorkExhausted,
            ));
        }
        let effect_request = PendingEffectRequest::new(
            request.kind(),
            request.operation(),
            request.frame(),
            request.attempts(),
            request.remaining_work(),
        );
        match effect.begin(effect_request, PendingWorkPermit::new(units)) {
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

    /// Performs one bounded resume transition.
    pub fn resume(mut self) -> PendingTransition<'provider, 'data, 'effect, Effect> {
        if !self.identity_matches() {
            return self.finish_failure(
                PendingFailureKind::ProviderMismatch,
                PendingDestructionCause::ProviderFailure,
            );
        }
        if !self.begin_attempt() {
            return self.finish_failure(
                PendingFailureKind::EffectAttemptsExhausted,
                PendingDestructionCause::Exhaustion,
            );
        }
        let cost_request = PendingEffectRequest::new(
            self.request.kind(),
            self.request.operation(),
            self.request.frame(),
            self.attempts,
            self.request.remaining_work(),
        );
        let units = match self.state.as_ref() {
            Some(state) => match self.effect.resume_cost(state, &cost_request) {
                Ok(units) => units,
                Err(kind) => {
                    return self.finish_failure(
                        PendingFailureKind::Provider(kind),
                        PendingDestructionCause::ProviderFailure,
                    );
                }
            },
            None => return self.invariant_failure(),
        };
        if units == 0 {
            return self.finish_failure(
                PendingFailureKind::InvalidWorkCharge,
                PendingDestructionCause::ProviderFailure,
            );
        }
        if !self.identity_matches() {
            return self.finish_failure(
                PendingFailureKind::ProviderMismatch,
                PendingDestructionCause::ProviderFailure,
            );
        }
        if self.request.charge_work(units).is_err() {
            return self.finish_failure(
                PendingFailureKind::WorkExhausted,
                PendingDestructionCause::Exhaustion,
            );
        }
        let request = PendingEffectRequest::new(
            self.request.kind(),
            self.request.operation(),
            self.request.frame(),
            self.attempts,
            self.request.remaining_work(),
        );
        let Some(state) = self.state.as_mut() else {
            return self.invariant_failure();
        };
        match self
            .effect
            .resume(state, request, PendingWorkPermit::new(units))
        {
            PendingStep::Complete => self.finish_complete(),
            PendingStep::Active => PendingTransition::Active(self),
            PendingStep::Retry(reason) => PendingTransition::Retry(self, reason),
            PendingStep::Backpressure(reason) => self.record_backpressure(reason),
            PendingStep::Failed(kind) => self.finish_failure(
                PendingFailureKind::Provider(kind),
                PendingDestructionCause::ProviderFailure,
            ),
        }
    }

    /// Requests cancellation and retains ownership until it is durable.
    pub fn cancel(mut self) -> PendingTransition<'provider, 'data, 'effect, Effect> {
        if !self.identity_matches() {
            return self.finish_failure(
                PendingFailureKind::ProviderMismatch,
                PendingDestructionCause::ProviderFailure,
            );
        }
        if !self.begin_attempt() {
            return self.finish_failure(
                PendingFailureKind::EffectAttemptsExhausted,
                PendingDestructionCause::Exhaustion,
            );
        }
        let cost_request = PendingEffectRequest::new(
            self.request.kind(),
            self.request.operation(),
            self.request.frame(),
            self.attempts,
            self.request.remaining_work(),
        );
        let units = match self.state.as_ref() {
            Some(state) => match self.effect.cancel_cost(state, &cost_request) {
                Ok(units) => units,
                Err(kind) => {
                    return self.finish_failure(
                        PendingFailureKind::Provider(kind),
                        PendingDestructionCause::ProviderFailure,
                    );
                }
            },
            None => return self.invariant_failure(),
        };
        if units == 0 {
            return self.finish_failure(
                PendingFailureKind::InvalidWorkCharge,
                PendingDestructionCause::ProviderFailure,
            );
        }
        if !self.identity_matches() {
            return self.finish_failure(
                PendingFailureKind::ProviderMismatch,
                PendingDestructionCause::ProviderFailure,
            );
        }
        if self.request.charge_work(units).is_err() {
            return self.finish_failure(
                PendingFailureKind::WorkExhausted,
                PendingDestructionCause::Exhaustion,
            );
        }
        let request = PendingEffectRequest::new(
            self.request.kind(),
            self.request.operation(),
            self.request.frame(),
            self.attempts,
            self.request.remaining_work(),
        );
        let Some(state) = self.state.as_mut() else {
            return self.invariant_failure();
        };
        match self
            .effect
            .cancel(state, request, PendingWorkPermit::new(units))
        {
            PendingCancelStep::Canceled => self.finish_canceled(),
            PendingCancelStep::Retry(reason) => PendingTransition::Retry(self, reason),
            PendingCancelStep::Backpressure(reason) => self.record_backpressure(reason),
            PendingCancelStep::Failed(kind) => self.finish_failure(
                PendingFailureKind::Provider(kind),
                PendingDestructionCause::ProviderFailure,
            ),
        }
    }

    fn identity_matches(&self) -> bool {
        self.request.is_bound_to(&self.effect.provider_handle())
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
        let Some(state) = self.state.as_mut() else {
            return Ok(());
        };
        let token = PendingDestructionToken::new(
            self.request.resource(),
            self.request.destruction_targets(),
            cause,
        );
        match self.effect.destroy(state, token) {
            PendingDestructionOutcome::Complete(_) => {
                let _destroyed = self.state.take();
                Ok(())
            }
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
