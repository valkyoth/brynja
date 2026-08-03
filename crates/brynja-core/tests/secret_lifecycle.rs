//! Secret-lifetime contract transition and destruction-duty tests.

use brynja_core::{
    DestructionCause, DestructionFailure, DestructionFailureKind, DestructionOutcome,
    DestructionTarget, DestructionTargets, InitializationTransition, ProviderFailure,
    ProviderFailureKind, ProviderOperation, ReplacementTransition, SecretContractError,
    SecretDestructor, SecretInitialization, SecretLifecycleContract, TargetDestructionStatus,
};

#[derive(Default)]
struct Recorder {
    local: usize,
    external: usize,
    accelerator: usize,
    cache: usize,
    dma: usize,
    fail: Option<DestructionTarget>,
    last_cause: Option<DestructionCause>,
    drop_failures: usize,
    drop_failure_cause: Option<DestructionCause>,
    drop_failure_kind: Option<DestructionFailureKind>,
    drop_failure_target: Option<DestructionTarget>,
}

impl Recorder {
    fn increment(value: &mut usize) {
        if let Some(next) = value.checked_add(1) {
            *value = next;
        }
    }

    fn total(&self) -> usize {
        let first = self.local.checked_add(self.external);
        let second = first.and_then(|value| value.checked_add(self.accelerator));
        let third = second.and_then(|value| value.checked_add(self.cache));
        third
            .and_then(|value| value.checked_add(self.dma))
            .unwrap_or_default()
    }
}

impl SecretDestructor for Recorder {
    fn destroy(
        &mut self,
        target: DestructionTarget,
        cause: DestructionCause,
    ) -> TargetDestructionStatus {
        self.last_cause = Some(cause);
        match target {
            DestructionTarget::LocalMemory => Self::increment(&mut self.local),
            DestructionTarget::ExternalStore => Self::increment(&mut self.external),
            DestructionTarget::Accelerator => Self::increment(&mut self.accelerator),
            DestructionTarget::Cache => Self::increment(&mut self.cache),
            DestructionTarget::Dma => Self::increment(&mut self.dma),
            _ => return TargetDestructionStatus::Failed,
        }
        if self.fail == Some(target) {
            TargetDestructionStatus::Failed
        } else {
            TargetDestructionStatus::Complete
        }
    }

    fn handle_drop_failure(&mut self, failure: DestructionFailure) {
        Self::increment(&mut self.drop_failures);
        self.drop_failure_cause = Some(failure.cause());
        self.drop_failure_kind = Some(failure.kind());
        self.drop_failure_target = failure.target();
    }
}

fn contract(region_bytes: usize, targets: DestructionTargets) -> SecretLifecycleContract {
    match SecretLifecycleContract::new(region_bytes, targets) {
        Ok(value) => value,
        Err(_) => {
            assert!(
                core::hint::black_box(false),
                "valid lifecycle contract was rejected"
            );
            loop {
                core::hint::spin_loop();
            }
        }
    }
}

fn assert_complete(outcome: DestructionOutcome, cause: DestructionCause) {
    match outcome {
        DestructionOutcome::Complete(token) => assert_eq!(token.cause(), cause),
        DestructionOutcome::Failed(_) => assert!(
            core::hint::black_box(false),
            "destruction unexpectedly failed"
        ),
    }
}

#[test]
fn all_initialization_boundaries_are_affine_and_exact() {
    for total in 1_usize..=8 {
        let mut recorder = Recorder::default();
        let policy = contract(total, DestructionTargets::local_memory());
        let initialization = SecretInitialization::begin(policy, &mut recorder);
        let initialization = match initialization.acknowledge_write(0) {
            InitializationTransition::Incomplete(value) => value,
            InitializationTransition::Readable(_) | InitializationTransition::Failed(_) => {
                return assert!(
                    core::hint::black_box(false),
                    "zero-byte acknowledgement changed phase"
                );
            }
        };
        let mut pending = Some(initialization);
        for step in 0_usize..total {
            let active = match pending.take() {
                Some(value) => value,
                None => {
                    return assert!(
                        core::hint::black_box(false),
                        "initialization completed too early"
                    );
                }
            };
            let completed = match step.checked_add(1) {
                Some(value) => value,
                None => {
                    return assert!(core::hint::black_box(false), "test counter overflowed");
                }
            };
            match active.acknowledge_write(1) {
                InitializationTransition::Incomplete(next) => {
                    assert!(completed < total);
                    pending = Some(next);
                }
                InitializationTransition::Readable(owner) => {
                    assert_eq!(completed, total);
                    assert_complete(owner.obsolete(), DestructionCause::Obsolete);
                }
                InitializationTransition::Failed(_) => {
                    return assert!(core::hint::black_box(false), "exact initialization failed");
                }
            }
        }
        assert!(pending.is_none());
        drop(pending);
        assert_eq!(recorder.local, 1);
        assert_eq!(recorder.total(), 1);
    }
}

#[test]
fn overrun_and_every_early_exit_destroy_partial_state() {
    let mut overrun = Recorder::default();
    let policy = contract(4, DestructionTargets::all());
    let initialization = SecretInitialization::begin(policy, &mut overrun);
    match initialization.acknowledge_write(5) {
        InitializationTransition::Failed(outcome) => {
            assert_complete(outcome, DestructionCause::InitializationFailure);
        }
        InitializationTransition::Incomplete(_) | InitializationTransition::Readable(_) => {
            return assert!(
                core::hint::black_box(false),
                "overrun escaped initialization"
            );
        }
    }
    assert_eq!(overrun.total(), 5);

    let mut canceled = Recorder::default();
    let policy = contract(4, DestructionTargets::local_memory());
    let initialization = SecretInitialization::begin(policy, &mut canceled);
    assert_complete(initialization.cancel(), DestructionCause::Cancellation);
    assert_eq!(canceled.local, 1);

    let mut exhausted = Recorder::default();
    let initialization = SecretInitialization::begin(policy, &mut exhausted);
    assert_complete(initialization.exhausted(), DestructionCause::Exhaustion);
    assert_eq!(exhausted.local, 1);

    let mut provider = Recorder::default();
    let initialization = SecretInitialization::begin(policy, &mut provider);
    let failure = ProviderFailure::new(
        ProviderOperation::KeyAgreement,
        ProviderFailureKind::InvalidOutput,
    );
    assert_complete(
        initialization.provider_failed(failure),
        DestructionCause::ProviderFailure,
    );
    assert_eq!(provider.local, 1);
}

#[test]
fn partial_and_readable_drop_request_immediate_destruction() {
    let mut partial = Recorder::default();
    {
        let policy = contract(3, DestructionTargets::all());
        let initialization = SecretInitialization::begin(policy, &mut partial);
        match initialization.acknowledge_write(1) {
            InitializationTransition::Incomplete(value) => drop(value),
            InitializationTransition::Readable(_) | InitializationTransition::Failed(_) => {
                return assert!(core::hint::black_box(false));
            }
        }
    }
    assert_eq!(partial.total(), 5);
    assert_eq!(
        partial.last_cause,
        Some(DestructionCause::InitializationFailure)
    );

    let mut readable = Recorder::default();
    {
        let policy = contract(1, DestructionTargets::all());
        let initialization = SecretInitialization::begin(policy, &mut readable);
        match initialization.acknowledge_write(1) {
            InitializationTransition::Readable(owner) => drop(owner),
            InitializationTransition::Incomplete(_) | InitializationTransition::Failed(_) => {
                return assert!(core::hint::black_box(false));
            }
        }
    }
    assert_eq!(readable.total(), 5);
    assert_eq!(readable.last_cause, Some(DestructionCause::Drop));
}

#[test]
fn replacement_destroys_old_state_before_new_state_exists() {
    let mut recorder = Recorder::default();
    let policy = contract(2, DestructionTargets::all());
    let initialization = SecretInitialization::begin(policy, &mut recorder);
    let owner = match initialization.acknowledge_write(2) {
        InitializationTransition::Readable(value) => value,
        InitializationTransition::Incomplete(_) | InitializationTransition::Failed(_) => {
            return assert!(core::hint::black_box(false));
        }
    };
    let next = match owner.replace(3) {
        ReplacementTransition::Initializing { previous, next } => {
            assert_eq!(previous.cause(), DestructionCause::Replacement);
            next
        }
        ReplacementTransition::Rejected { .. } | ReplacementTransition::Failed(_) => {
            return assert!(core::hint::black_box(false));
        }
    };
    let next_owner = match next.acknowledge_write(3) {
        InitializationTransition::Readable(value) => value,
        InitializationTransition::Incomplete(_) | InitializationTransition::Failed(_) => {
            return assert!(core::hint::black_box(false));
        }
    };
    assert_complete(next_owner.obsolete(), DestructionCause::Obsolete);
    assert_eq!(recorder.local, 2);
    assert_eq!(recorder.external, 2);
    assert_eq!(recorder.accelerator, 2);
    assert_eq!(recorder.cache, 2);
    assert_eq!(recorder.dma, 2);
}

#[test]
fn reject_invalid_and_exhausted() {
    let empty = SecretLifecycleContract::new(0, DestructionTargets::local_memory());
    assert!(matches!(empty, Err(SecretContractError::EmptyRegion)));
    let no_targets = SecretLifecycleContract::new(
        1,
        DestructionTargets::new(false, false, false, false, false),
    );
    assert!(matches!(
        no_targets,
        Err(SecretContractError::NoDestructionTarget)
    ));

    let mut recorder = Recorder::default();
    let policy = contract(1, DestructionTargets::local_memory());
    let start = SecretInitialization::begin(policy, &mut recorder);
    let owner = match start.acknowledge_write(1) {
        InitializationTransition::Readable(value) => value,
        InitializationTransition::Incomplete(_) | InitializationTransition::Failed(_) => {
            return assert!(core::hint::black_box(false));
        }
    };
    match owner.replace(0) {
        ReplacementTransition::Rejected { previous, error } => {
            assert_eq!(previous.cause(), DestructionCause::Replacement);
            assert_eq!(error, SecretContractError::EmptyRegion);
        }
        ReplacementTransition::Initializing { .. } | ReplacementTransition::Failed(_) => {
            return assert!(core::hint::black_box(false));
        }
    }
    assert_eq!(recorder.local, 1);
}

#[test]
fn target_failure_attempts_every_duty_and_is_terminal() {
    let mut recorder = Recorder {
        fail: Some(DestructionTarget::Accelerator),
        ..Recorder::default()
    };
    let policy = contract(1, DestructionTargets::all());
    let initialization = SecretInitialization::begin(policy, &mut recorder);
    let owner = match initialization.acknowledge_write(1) {
        InitializationTransition::Readable(value) => value,
        InitializationTransition::Incomplete(_) | InitializationTransition::Failed(_) => {
            return assert!(core::hint::black_box(false));
        }
    };
    match owner.obsolete() {
        DestructionOutcome::Failed(failure) => {
            assert_eq!(failure.cause(), DestructionCause::Obsolete);
            assert_eq!(failure.kind(), DestructionFailureKind::TargetFailed);
            assert_eq!(failure.target(), Some(DestructionTarget::Accelerator));
        }
        DestructionOutcome::Complete(_) => return assert!(core::hint::black_box(false)),
    }
    assert_eq!(recorder.total(), 5);
}

#[test]
fn failing_drop_notifies_the_mandatory_terminal_handler() {
    let mut partial = Recorder {
        fail: Some(DestructionTarget::Cache),
        ..Recorder::default()
    };
    {
        let policy = contract(2, DestructionTargets::all());
        let initialization = SecretInitialization::begin(policy, &mut partial);
        drop(initialization);
    }
    assert_eq!(partial.total(), 5);
    assert_eq!(partial.drop_failures, 1);
    assert_eq!(
        partial.drop_failure_cause,
        Some(DestructionCause::InitializationFailure)
    );
    assert_eq!(
        partial.drop_failure_kind,
        Some(DestructionFailureKind::TargetFailed)
    );
    assert_eq!(partial.drop_failure_target, Some(DestructionTarget::Cache));

    let mut readable = Recorder {
        fail: Some(DestructionTarget::Dma),
        ..Recorder::default()
    };
    {
        let policy = contract(1, DestructionTargets::all());
        let initialization = SecretInitialization::begin(policy, &mut readable);
        match initialization.acknowledge_write(1) {
            InitializationTransition::Readable(owner) => drop(owner),
            InitializationTransition::Incomplete(_) | InitializationTransition::Failed(_) => {
                return assert!(core::hint::black_box(false));
            }
        }
    }
    assert_eq!(readable.total(), 5);
    assert_eq!(readable.drop_failures, 1);
    assert_eq!(readable.drop_failure_cause, Some(DestructionCause::Drop));
    assert_eq!(
        readable.drop_failure_kind,
        Some(DestructionFailureKind::TargetFailed)
    );
    assert_eq!(readable.drop_failure_target, Some(DestructionTarget::Dma));
}

#[test]
fn target_sets_are_exact_and_diagnostic_values_are_closed() {
    let targets = DestructionTargets::new(true, false, true, false, true);
    assert!(targets.contains(DestructionTarget::LocalMemory));
    assert!(!targets.contains(DestructionTarget::ExternalStore));
    assert!(targets.contains(DestructionTarget::Accelerator));
    assert!(!targets.contains(DestructionTarget::Cache));
    assert!(targets.contains(DestructionTarget::Dma));

    assert_eq!(
        format!("{:?}", SecretContractError::EmptyRegion),
        "EmptyRegion"
    );
    assert!(!core::mem::needs_drop::<DestructionTargets>());
}
