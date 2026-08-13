//! Deterministic pending-provider fixture shared by lifecycle tests.

#![allow(dead_code)]

use brynja_core::{
    DestructionTargets, PendingBackpressure, PendingBegin, PendingCancelStep,
    PendingDestructionCause, PendingDestructionFailure, PendingDestructionFailureKind,
    PendingDestructionOutcome, PendingDestructionToken, PendingEffectRequest, PendingLimits,
    PendingProvider, PendingRetryReason, PendingStep, PendingWorkPermit, ProviderCapabilities,
    ProviderFailureKind, ProviderFrame, ProviderHandle, ProviderInstallation, ProviderOperation,
    ResourceBudget, WorkBudget,
};

#[derive(Clone, Copy)]
pub(crate) enum Step {
    Active,
    Retry,
    Backpressure,
    Complete,
    Failed,
}

pub(crate) struct State {
    cursor: usize,
}

pub(crate) struct DeterministicProvider<'provider> {
    provider: &'provider brynja_core::InstalledProvider,
    begin: Option<PendingBegin<State>>,
    resume: &'static [Step],
    cancel: &'static [Step],
    pub(crate) destroy_failure: Option<PendingDestructionFailureKind>,
    pub(crate) destroyed: usize,
    pub(crate) drop_failures: usize,
    pub(crate) last_cause: Option<PendingDestructionCause>,
    pub(crate) step_cost: u64,
    pub(crate) charged_units: u64,
    pub(crate) panic_resume: bool,
    pub(crate) panic_cancel: bool,
}

impl<'provider> DeterministicProvider<'provider> {
    pub(crate) fn active(
        provider: &'provider brynja_core::InstalledProvider,
        resume: &'static [Step],
        cancel: &'static [Step],
    ) -> Self {
        Self {
            provider,
            begin: Some(PendingBegin::Active(State { cursor: 0 })),
            resume,
            cancel,
            destroy_failure: None,
            destroyed: 0,
            drop_failures: 0,
            last_cause: None,
            step_cost: 1,
            charged_units: 0,
            panic_resume: false,
            panic_cancel: false,
        }
    }

    pub(crate) fn begin_once(
        provider: &'provider brynja_core::InstalledProvider,
        begin: PendingBegin<State>,
    ) -> Self {
        Self {
            provider,
            begin: Some(begin),
            resume: &[],
            cancel: &[],
            destroy_failure: None,
            destroyed: 0,
            drop_failures: 0,
            last_cause: None,
            step_cost: 1,
            charged_units: 0,
            panic_resume: false,
            panic_cancel: false,
        }
    }

    fn step(state: &mut State, script: &[Step]) -> Step {
        let step = script.get(state.cursor).copied().unwrap_or(Step::Failed);
        state.cursor = state.cursor.checked_add(1).unwrap_or(state.cursor);
        step
    }
}

impl PendingProvider for DeterministicProvider<'_> {
    type State = State;

    fn provider_handle(&self) -> ProviderHandle<'_> {
        self.provider.handle()
    }

    fn begin_cost(
        &self,
        _request: &PendingEffectRequest<'_, '_>,
    ) -> Result<u64, ProviderFailureKind> {
        Ok(self.step_cost)
    }

    fn begin(
        &mut self,
        request: PendingEffectRequest<'_, '_>,
        permit: PendingWorkPermit,
    ) -> PendingBegin<Self::State> {
        assert!(request.attempt() >= 1);
        assert_eq!(permit.units(), self.step_cost);
        self.charged_units = self.charged_units.saturating_add(permit.units());
        self.begin
            .take()
            .unwrap_or(PendingBegin::Failed(ProviderFailureKind::Failed))
    }

    fn resume_cost(
        &self,
        _state: &Self::State,
        _request: &PendingEffectRequest<'_, '_>,
    ) -> Result<u64, ProviderFailureKind> {
        Ok(self.step_cost)
    }

    fn resume(
        &mut self,
        state: &mut Self::State,
        request: PendingEffectRequest<'_, '_>,
        permit: PendingWorkPermit,
    ) -> PendingStep {
        assert!(request.attempt() >= 2);
        assert_eq!(permit.units(), self.step_cost);
        self.charged_units = self.charged_units.saturating_add(permit.units());
        assert!(!self.panic_resume, "injected resume panic");
        let step = Self::step(state, self.resume);
        match step {
            Step::Active => PendingStep::Active,
            Step::Retry => PendingStep::Retry(PendingRetryReason::NotReady),
            Step::Backpressure => PendingStep::Backpressure(PendingBackpressure::DeviceBusy),
            Step::Complete => PendingStep::Complete,
            Step::Failed => PendingStep::Failed(ProviderFailureKind::Failed),
        }
    }

    fn cancel_cost(
        &self,
        _state: &Self::State,
        _request: &PendingEffectRequest<'_, '_>,
    ) -> Result<u64, ProviderFailureKind> {
        Ok(self.step_cost)
    }

    fn cancel(
        &mut self,
        state: &mut Self::State,
        request: PendingEffectRequest<'_, '_>,
        permit: PendingWorkPermit,
    ) -> PendingCancelStep {
        assert!(request.attempt() >= 2);
        assert_eq!(permit.units(), self.step_cost);
        self.charged_units = self.charged_units.saturating_add(permit.units());
        assert!(!self.panic_cancel, "injected cancel panic");
        let step = Self::step(state, self.cancel);
        match step {
            Step::Active | Step::Retry => {
                PendingCancelStep::Retry(PendingRetryReason::CancellationInProgress)
            }
            Step::Backpressure => PendingCancelStep::Backpressure(PendingBackpressure::QueueFull),
            Step::Complete => PendingCancelStep::Canceled,
            Step::Failed => PendingCancelStep::Failed(ProviderFailureKind::Failed),
        }
    }

    fn destroy(
        &mut self,
        _state: &mut Self::State,
        token: PendingDestructionToken,
    ) -> PendingDestructionOutcome {
        self.destroyed = self.destroyed.checked_add(1).unwrap_or(self.destroyed);
        self.last_cause = Some(token.cause());
        if let Some(kind) = self.destroy_failure {
            token.fail(kind)
        } else {
            token.complete()
        }
    }

    fn handle_drop_failure(&mut self, _failure: PendingDestructionFailure) {
        self.drop_failures = self
            .drop_failures
            .checked_add(1)
            .unwrap_or(self.drop_failures);
    }
}

fn capabilities(operation: ProviderOperation, poll: bool, cancel: bool) -> ProviderCapabilities {
    let builder = ProviderCapabilities::builder()
        .enable(operation)
        .unwrap_or_else(|_| unreachable!());
    let builder = if poll {
        builder
            .enable(ProviderOperation::PendingPoll)
            .unwrap_or_else(|_| unreachable!())
    } else {
        builder
    };
    let builder = if cancel {
        builder
            .enable(ProviderOperation::PendingCancel)
            .unwrap_or_else(|_| unreachable!())
    } else {
        builder
    };
    builder.freeze().unwrap_or_else(|_| unreachable!())
}

fn resources() -> ResourceBudget {
    ResourceBudget::builder()
        .input_bytes(32)
        .and_then(|value| value.output_bytes(32))
        .and_then(|value| value.workspace_bytes(32))
        .and_then(|value| value.state_items(4))
        .and_then(|value| value.queue_items(4))
        .and_then(|value| value.certificate_bytes(32))
        .and_then(|value| value.provider_operations(8))
        .and_then(|value| value.build())
        .unwrap_or_else(|_| unreachable!())
}

pub(crate) fn installed(
    operation: ProviderOperation,
    targets: DestructionTargets,
    poll: bool,
    cancel: bool,
) -> brynja_core::InstalledProvider {
    ProviderInstallation::begin()
        .capabilities(capabilities(operation, poll, cancel))
        .and_then(|value| value.resources(resources()))
        .and_then(|value| value.work(WorkBudget::new(32)))
        .and_then(|value| value.destruction_targets(targets))
        .and_then(ProviderInstallation::install)
        .unwrap_or_else(|_| unreachable!())
}

pub(crate) fn prepared<'provider, 'data>(
    provider: &'provider brynja_core::InstalledProvider,
    operation: ProviderOperation,
    bytes: &'data [u8],
) -> brynja_core::ProviderRequest<'provider, 'data> {
    provider
        .handle()
        .authorize(operation)
        .and_then(|authorization| {
            authorization
                .prepare(ProviderFrame::new(bytes, &[], 0))
                .map_err(|_| brynja_core::ProviderAuthorizationError::Unsupported(operation))
        })
        .unwrap_or_else(|_| unreachable!())
}

pub(crate) fn limits(attempts: u64, backpressure: u64) -> PendingLimits {
    PendingLimits::new(attempts, backpressure).unwrap_or_else(|_| unreachable!())
}
