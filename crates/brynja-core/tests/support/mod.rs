//! Deterministic pending-provider fixture shared by lifecycle tests.

use brynja_core::{
    DestructionTargets, PendingBackpressure, PendingBegin, PendingCancelStep,
    PendingDestructionCause, PendingDestructionFailure, PendingDestructionFailureKind,
    PendingDestructionOutcome, PendingDestructionToken, PendingEffectRequest, PendingLimits,
    PendingProvider, PendingRetryReason, PendingStep, ProviderCapabilities, ProviderFailureKind,
    ProviderFrame, ProviderInstallation, ProviderOperation, ResourceBudget, WorkBudget,
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

pub(crate) struct DeterministicProvider {
    begin: Option<PendingBegin<State>>,
    resume: &'static [Step],
    cancel: &'static [Step],
    pub(crate) destroy_failure: Option<PendingDestructionFailureKind>,
    pub(crate) destroyed: usize,
    pub(crate) drop_failures: usize,
    pub(crate) last_cause: Option<PendingDestructionCause>,
}

impl DeterministicProvider {
    pub(crate) fn active(resume: &'static [Step], cancel: &'static [Step]) -> Self {
        Self {
            begin: Some(PendingBegin::Active(State { cursor: 0 })),
            resume,
            cancel,
            destroy_failure: None,
            destroyed: 0,
            drop_failures: 0,
            last_cause: None,
        }
    }

    pub(crate) fn begin_once(begin: PendingBegin<State>) -> Self {
        Self {
            begin: Some(begin),
            resume: &[],
            cancel: &[],
            destroy_failure: None,
            destroyed: 0,
            drop_failures: 0,
            last_cause: None,
        }
    }

    fn step(state: State, script: &[Step]) -> (State, Step) {
        let step = script.get(state.cursor).copied().unwrap_or(Step::Failed);
        let cursor = state.cursor.checked_add(1).unwrap_or(state.cursor);
        (State { cursor }, step)
    }
}

impl PendingProvider for DeterministicProvider {
    type State = State;

    fn begin(&mut self, request: PendingEffectRequest<'_, '_>) -> PendingBegin<Self::State> {
        assert!(request.attempt() >= 1);
        self.begin
            .take()
            .unwrap_or(PendingBegin::Failed(ProviderFailureKind::Failed))
    }

    fn resume(
        &mut self,
        state: Self::State,
        request: PendingEffectRequest<'_, '_>,
    ) -> PendingStep<Self::State> {
        assert!(request.attempt() >= 2);
        let (state, step) = Self::step(state, self.resume);
        match step {
            Step::Active => PendingStep::Active(state),
            Step::Retry => PendingStep::Retry(state, PendingRetryReason::NotReady),
            Step::Backpressure => PendingStep::Backpressure(state, PendingBackpressure::DeviceBusy),
            Step::Complete => PendingStep::Complete(state),
            Step::Failed => PendingStep::Failed(state, ProviderFailureKind::Failed),
        }
    }

    fn cancel(
        &mut self,
        state: Self::State,
        request: PendingEffectRequest<'_, '_>,
    ) -> PendingCancelStep<Self::State> {
        assert!(request.attempt() >= 2);
        let (state, step) = Self::step(state, self.cancel);
        match step {
            Step::Active | Step::Retry => {
                PendingCancelStep::Retry(state, PendingRetryReason::CancellationInProgress)
            }
            Step::Backpressure => {
                PendingCancelStep::Backpressure(state, PendingBackpressure::QueueFull)
            }
            Step::Complete => PendingCancelStep::Canceled(state),
            Step::Failed => PendingCancelStep::Failed(state, ProviderFailureKind::Failed),
        }
    }

    fn destroy(
        &mut self,
        _state: Self::State,
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
