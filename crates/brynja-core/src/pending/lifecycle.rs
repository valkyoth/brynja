//! Failure-atomic ownership of one pending provider operation.

use crate::ProviderOperation;

use super::{
    PendingBackpressure, PendingBeginStep, PendingCancelStep, PendingCancellation,
    PendingCompletion, PendingDestructionCause, PendingDestructionFailure,
    PendingDestructionFailureKind, PendingDestructionOutcome, PendingDestructionToken,
    PendingEffectRequest, PendingFailure, PendingFailureKind, PendingProvider, PendingRequest,
    PendingRequestKind, PendingStart, PendingStep, PendingTransition, PendingWorkPermit,
};

/// Affine ownership of one exact pending provider operation.
/// Drop destroys provider state; failures use [`PendingProvider::handle_drop_failure`].
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
    request: Option<PendingRequest<'provider, 'data>>,
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
        let prepare_request = PendingEffectRequest::new(
            request.kind(),
            request.operation(),
            request.frame(),
            request.attempts(),
            request.remaining_work(),
        );
        let state = match effect.prepare_state(&prepare_request) {
            Ok(state) => state,
            Err(kind) => {
                return PendingStart::Failed(failure_from_request(
                    &request,
                    PendingFailureKind::Provider(kind),
                ));
            }
        };
        let attempts = request.attempts();
        let backpressure = request.backpressure();
        let mut operation = Self {
            request: Some(request),
            state: Some(state),
            effect,
            attempts,
            backpressure,
        };
        if !operation.identity_matches() {
            return PendingStart::Failed(
                operation.finish_begin_failure(PendingFailureKind::ProviderMismatch),
            );
        }
        let guarded_request = operation
            .request
            .as_ref()
            .unwrap_or_else(|| unreachable!("pending request ownership invariant"));
        let effect_request = PendingEffectRequest::new(
            guarded_request.kind(),
            guarded_request.operation(),
            guarded_request.frame(),
            operation.attempts,
            guarded_request.remaining_work(),
        );
        let step = match operation.state.as_mut() {
            Some(state) => {
                operation
                    .effect
                    .begin(state, effect_request, PendingWorkPermit::new(units))
            }
            None => return PendingStart::Failed(operation.invariant_failure_value()),
        };
        match step {
            PendingBeginStep::Active => PendingStart::Active(operation),
            PendingBeginStep::Retry(reason) => match operation.recover_request() {
                Ok(request) => PendingStart::Retry(request, reason),
                Err(failure) => PendingStart::Failed(failure),
            },
            PendingBeginStep::Backpressure(reason) => match operation.recover_request() {
                Ok(mut request) => {
                    if request.record_backpressure() {
                        PendingStart::Backpressure(request, reason)
                    } else {
                        PendingStart::Failed(failure_from_request(
                            &request,
                            PendingFailureKind::BackpressureExhausted,
                        ))
                    }
                }
                Err(failure) => PendingStart::Failed(failure),
            },
            PendingBeginStep::Failed(kind) => PendingStart::Failed(
                operation.finish_begin_failure(PendingFailureKind::Provider(kind)),
            ),
        }
    }

    /// Returns the exact pending boundary.
    #[must_use]
    pub fn request_kind(&self) -> PendingRequestKind {
        self.request_ref().kind()
    }

    /// Returns the exact original provider operation.
    #[must_use]
    pub fn operation(&self) -> ProviderOperation {
        self.request_ref().operation()
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

    fn request_ref(&self) -> &PendingRequest<'provider, 'data> {
        self.request
            .as_ref()
            .unwrap_or_else(|| unreachable!("pending request ownership invariant"))
    }

    fn request_mut(&mut self) -> &mut PendingRequest<'provider, 'data> {
        self.request
            .as_mut()
            .unwrap_or_else(|| unreachable!("pending request ownership invariant"))
    }

    fn recover_request(mut self) -> Result<PendingRequest<'provider, 'data>, PendingFailure> {
        if let Err(failure) = self.destroy(PendingDestructionCause::Activation) {
            return Err(self.destruction_failure(failure));
        }
        self.request
            .take()
            .ok_or_else(|| self.invariant_failure_value())
    }

    fn finish_begin_failure(mut self, kind: PendingFailureKind) -> PendingFailure {
        match self.destroy(PendingDestructionCause::ProviderFailure) {
            Ok(()) => failure_from_request(self.request_ref(), kind),
            Err(failure) => self.destruction_failure(failure),
        }
    }

    fn invariant_failure_value(&self) -> PendingFailure {
        failure_from_request(
            self.request_ref(),
            PendingFailureKind::Destruction(PendingDestructionFailureKind::ProviderState),
        )
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
            self.request_ref().kind(),
            self.request_ref().operation(),
            self.request_ref().frame(),
            self.attempts,
            self.request_ref().remaining_work(),
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
        if self.request_mut().charge_work(units).is_err() {
            return self.finish_failure(
                PendingFailureKind::WorkExhausted,
                PendingDestructionCause::Exhaustion,
            );
        }
        let guarded_request = self
            .request
            .as_ref()
            .unwrap_or_else(|| unreachable!("pending request ownership invariant"));
        let request = PendingEffectRequest::new(
            guarded_request.kind(),
            guarded_request.operation(),
            guarded_request.frame(),
            self.attempts,
            guarded_request.remaining_work(),
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
            self.request_ref().kind(),
            self.request_ref().operation(),
            self.request_ref().frame(),
            self.attempts,
            self.request_ref().remaining_work(),
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
        if self.request_mut().charge_work(units).is_err() {
            return self.finish_failure(
                PendingFailureKind::WorkExhausted,
                PendingDestructionCause::Exhaustion,
            );
        }
        let guarded_request = self
            .request
            .as_ref()
            .unwrap_or_else(|| unreachable!("pending request ownership invariant"));
        let request = PendingEffectRequest::new(
            guarded_request.kind(),
            guarded_request.operation(),
            guarded_request.frame(),
            self.attempts,
            guarded_request.remaining_work(),
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
        self.request_ref()
            .is_bound_to(&self.effect.provider_handle())
    }

    fn begin_attempt(&mut self) -> bool {
        let Some(next) = self.attempts.checked_add(1) else {
            return false;
        };
        if next > self.request_ref().limits().effect_attempts() {
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
            Some(value) if value <= self.request_ref().limits().backpressure_responses() => {
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
                request_kind: self.request_ref().kind(),
                operation: self.request_ref().operation(),
                resource: self.request_ref().resource(),
            }),
            Err(failure) => PendingTransition::Failed(self.destruction_failure(failure)),
        }
    }

    fn finish_canceled(mut self) -> PendingTransition<'provider, 'data, 'effect, Effect> {
        match self.destroy(PendingDestructionCause::Cancellation) {
            Ok(()) => PendingTransition::Canceled(PendingCancellation {
                request_kind: self.request_ref().kind(),
                operation: self.request_ref().operation(),
                resource: self.request_ref().resource(),
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
            Ok(()) => PendingTransition::Failed(failure_from_request(self.request_ref(), kind)),
            Err(failure) => PendingTransition::Failed(self.destruction_failure(failure)),
        }
    }

    fn invariant_failure(self) -> PendingTransition<'provider, 'data, 'effect, Effect> {
        PendingTransition::Failed(failure_from_request(
            self.request_ref(),
            PendingFailureKind::Destruction(PendingDestructionFailureKind::ProviderState),
        ))
    }

    fn destroy(&mut self, cause: PendingDestructionCause) -> Result<(), PendingDestructionFailure> {
        if self.state.is_none() {
            return Ok(());
        }
        let resource = self.request_ref().resource();
        let targets = self.request_ref().destruction_targets();
        let Some(state) = self.state.as_mut() else {
            return Ok(());
        };
        let token = PendingDestructionToken::new(resource, targets, cause);
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
            self.request_ref(),
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
