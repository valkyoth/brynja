//! Pending-operation admission, lifecycle, and destruction tests.

mod support;

use brynja_core::{
    DestructionTarget, DestructionTargets, PendingBackpressure, PendingBegin,
    PendingDestructionCause, PendingDestructionFailureKind, PendingFailureKind, PendingLimitError,
    PendingLimits, PendingOperation, PendingRequest, PendingRequestError, PendingRequestKind,
    PendingResource, PendingRetryReason, PendingStart, PendingTransition, ProviderFailureKind,
    ProviderOperation,
};
use support::{DeterministicProvider, Step, installed, limits, prepared};

#[test]
fn admission_is_exact_and_requires_poll_cancel_and_destruction_duties() {
    assert!(matches!(
        PendingLimits::new(0, 1),
        Err(PendingLimitError::ZeroEffectAttempts)
    ));
    assert!(matches!(
        PendingLimits::new(1, 0),
        Err(PendingLimitError::ZeroBackpressureResponses)
    ));

    let no_poll = installed(
        ProviderOperation::Sign,
        DestructionTargets::all(),
        false,
        true,
    );
    assert!(matches!(
        PendingRequest::signature(
            prepared(&no_poll, ProviderOperation::Sign, b"message"),
            limits(2, 1),
        ),
        Err(PendingRequestError::MissingCapability(
            ProviderOperation::PendingPoll
        ))
    ));

    let local = installed(
        ProviderOperation::Sign,
        DestructionTargets::local_memory(),
        true,
        true,
    );
    assert!(matches!(
        PendingRequest::signature(
            prepared(&local, ProviderOperation::Sign, b"message"),
            limits(2, 1),
        ),
        Err(PendingRequestError::MissingDestructionTarget(
            DestructionTarget::ExternalStore
        ))
    ));
    assert!(matches!(
        PendingRequest::accelerator(
            prepared(&local, ProviderOperation::Sign, b"message"),
            limits(2, 1),
        ),
        Err(PendingRequestError::WrongOperation(ProviderOperation::Sign))
    ));

    let certificate = installed(
        ProviderOperation::CertificatePath,
        DestructionTargets::local_memory(),
        true,
        true,
    );
    assert!(matches!(
        PendingRequest::accelerator(
            prepared(&certificate, ProviderOperation::CertificatePath, b"chain"),
            limits(2, 1),
        ),
        Err(PendingRequestError::WrongOperation(
            ProviderOperation::CertificatePath
        ))
    ));
    assert!(
        PendingRequest::certificate(
            prepared(&certificate, ProviderOperation::CertificatePath, b"chain"),
            limits(2, 1),
        )
        .is_ok()
    );
}

#[test]
fn begin_retry_and_backpressure_return_the_same_affine_request() {
    let provider = installed(
        ProviderOperation::AeadSeal,
        DestructionTargets::all(),
        true,
        true,
    );
    let input = [0xa5; 8];
    let request = PendingRequest::accelerator(
        prepared(&provider, ProviderOperation::AeadSeal, &input),
        limits(3, 1),
    )
    .unwrap_or_else(|_| unreachable!());
    let mut retry = DeterministicProvider::begin_once(
        &provider,
        PendingBegin::Retry(PendingRetryReason::TransientFailure),
    );
    let request = match PendingOperation::begin(request, &mut retry) {
        PendingStart::Retry(request, PendingRetryReason::TransientFailure) => request,
        _ => unreachable!(),
    };
    let mut blocked = DeterministicProvider::begin_once(
        &provider,
        PendingBegin::Backpressure(PendingBackpressure::DeviceBusy),
    );
    let request = match PendingOperation::begin(request, &mut blocked) {
        PendingStart::Backpressure(request, PendingBackpressure::DeviceBusy) => request,
        _ => unreachable!(),
    };
    let mut blocked_again = DeterministicProvider::begin_once(
        &provider,
        PendingBegin::Backpressure(PendingBackpressure::DeviceBusy),
    );
    assert!(matches!(
        PendingOperation::begin(request, &mut blocked_again),
        PendingStart::Failed(failure)
            if failure.kind() == PendingFailureKind::BackpressureExhausted
    ));
    assert_eq!(input, [0xa5; 8]);
}

#[test]
fn resume_is_deterministic_bounded_and_destroys_exactly_once() {
    let provider = installed(
        ProviderOperation::Hash,
        DestructionTargets::all(),
        true,
        true,
    );
    let request = PendingRequest::accelerator(
        prepared(&provider, ProviderOperation::Hash, b"input"),
        limits(5, 2),
    )
    .unwrap_or_else(|_| unreachable!());
    let mut effect = DeterministicProvider::active(
        &provider,
        &[
            Step::Active,
            Step::Retry,
            Step::Backpressure,
            Step::Complete,
        ],
        &[],
    );
    let operation = match PendingOperation::begin(request, &mut effect) {
        PendingStart::Active(operation) => operation,
        _ => unreachable!(),
    };
    let operation = match operation.resume() {
        PendingTransition::Active(operation) => operation,
        _ => unreachable!(),
    };
    let operation = match operation.resume() {
        PendingTransition::Retry(operation, PendingRetryReason::NotReady) => operation,
        _ => unreachable!(),
    };
    let operation = match operation.resume() {
        PendingTransition::Backpressure(operation, PendingBackpressure::DeviceBusy) => operation,
        _ => unreachable!(),
    };
    let complete = match operation.resume() {
        PendingTransition::Complete(complete) => complete,
        _ => unreachable!(),
    };
    assert_eq!(complete.request_kind(), PendingRequestKind::Accelerator);
    assert_eq!(complete.operation(), ProviderOperation::Hash);
    assert_eq!(complete.resource(), PendingResource::AcceleratorHandle);
    assert_eq!(effect.destroyed, 1);
    assert_eq!(effect.last_cause, Some(PendingDestructionCause::Completion));
}

#[test]
fn cancellation_retries_then_completes_authoritatively() {
    let provider = installed(
        ProviderOperation::Sign,
        DestructionTargets::all(),
        true,
        true,
    );
    let request = PendingRequest::signature(
        prepared(&provider, ProviderOperation::Sign, b"message"),
        limits(4, 2),
    )
    .unwrap_or_else(|_| unreachable!());
    let mut effect = DeterministicProvider::active(
        &provider,
        &[],
        &[Step::Retry, Step::Backpressure, Step::Complete],
    );
    let operation = match PendingOperation::begin(request, &mut effect) {
        PendingStart::Active(operation) => operation,
        _ => unreachable!(),
    };
    let operation = match operation.cancel() {
        PendingTransition::Retry(operation, PendingRetryReason::CancellationInProgress) => {
            operation
        }
        _ => unreachable!(),
    };
    let operation = match operation.cancel() {
        PendingTransition::Backpressure(operation, PendingBackpressure::QueueFull) => operation,
        _ => unreachable!(),
    };
    let canceled = match operation.cancel() {
        PendingTransition::Canceled(canceled) => canceled,
        _ => unreachable!(),
    };
    assert_eq!(canceled.request_kind(), PendingRequestKind::Signature);
    assert_eq!(canceled.resource(), PendingResource::ExternalKey);
    assert_eq!(effect.destroyed, 1);
    assert_eq!(
        effect.last_cause,
        Some(PendingDestructionCause::Cancellation)
    );
}

#[test]
fn exhaustion_failure_and_drop_all_run_terminal_cleanup() {
    let provider = installed(
        ProviderOperation::Hash,
        DestructionTargets::all(),
        true,
        true,
    );
    let make = || {
        PendingRequest::accelerator(
            prepared(&provider, ProviderOperation::Hash, b"input"),
            limits(2, 1),
        )
        .unwrap_or_else(|_| unreachable!())
    };

    let mut exhaustion = DeterministicProvider::active(&provider, &[Step::Retry], &[]);
    let operation = match PendingOperation::begin(make(), &mut exhaustion) {
        PendingStart::Active(operation) => operation,
        _ => unreachable!(),
    };
    let operation = match operation.resume() {
        PendingTransition::Retry(operation, _) => operation,
        _ => unreachable!(),
    };
    assert!(matches!(
        operation.resume(),
        PendingTransition::Failed(failure)
            if failure.kind() == PendingFailureKind::EffectAttemptsExhausted
    ));
    assert_eq!(exhaustion.destroyed, 1);
    assert_eq!(
        exhaustion.last_cause,
        Some(PendingDestructionCause::Exhaustion)
    );

    let mut failure = DeterministicProvider::active(&provider, &[Step::Failed], &[]);
    let operation = match PendingOperation::begin(make(), &mut failure) {
        PendingStart::Active(operation) => operation,
        _ => unreachable!(),
    };
    assert!(matches!(
        operation.resume(),
        PendingTransition::Failed(value)
            if value.kind() == PendingFailureKind::Provider(ProviderFailureKind::Failed)
    ));
    assert_eq!(failure.destroyed, 1);
    assert_eq!(
        failure.last_cause,
        Some(PendingDestructionCause::ProviderFailure)
    );

    let mut dropped = DeterministicProvider::active(&provider, &[], &[]);
    {
        let operation = match PendingOperation::begin(make(), &mut dropped) {
            PendingStart::Active(operation) => operation,
            _ => unreachable!(),
        };
        drop(operation);
    }
    assert_eq!(dropped.destroyed, 1);
    assert_eq!(dropped.last_cause, Some(PendingDestructionCause::Drop));
}

#[test]
fn destruction_failure_overrides_success_and_drop_is_reported() {
    let provider = installed(
        ProviderOperation::Sign,
        DestructionTargets::all(),
        true,
        true,
    );
    let make = || {
        PendingRequest::signature(
            prepared(&provider, ProviderOperation::Sign, b"message"),
            limits(2, 1),
        )
        .unwrap_or_else(|_| unreachable!())
    };
    let mut explicit = DeterministicProvider::active(&provider, &[Step::Complete], &[]);
    explicit.destroy_failure = Some(PendingDestructionFailureKind::ExternalKey);
    let operation = match PendingOperation::begin(make(), &mut explicit) {
        PendingStart::Active(operation) => operation,
        _ => unreachable!(),
    };
    assert!(matches!(
        operation.resume(),
        PendingTransition::Failed(failure)
            if failure.kind()
                == PendingFailureKind::Destruction(
                    PendingDestructionFailureKind::ExternalKey
                )
    ));
    assert_eq!(explicit.destroyed, 2);
    assert_eq!(explicit.drop_failures, 1);

    let accelerator = installed(
        ProviderOperation::Hash,
        DestructionTargets::all(),
        true,
        true,
    );
    let mut dropped = DeterministicProvider::active(&accelerator, &[], &[]);
    dropped.destroy_failure = Some(PendingDestructionFailureKind::AcceleratorHandle);
    {
        let request = PendingRequest::accelerator(
            prepared(&accelerator, ProviderOperation::Hash, b"input"),
            limits(2, 1),
        )
        .unwrap_or_else(|_| unreachable!());
        let operation = match PendingOperation::begin(request, &mut dropped) {
            PendingStart::Active(operation) => operation,
            _ => unreachable!(),
        };
        drop(operation);
    }
    assert_eq!(dropped.destroyed, 1);
    assert_eq!(dropped.drop_failures, 1);
}

#[test]
fn begin_failure_creates_no_cleanup_claim() {
    let provider = installed(
        ProviderOperation::CertificatePath,
        DestructionTargets::local_memory(),
        true,
        true,
    );
    let request = PendingRequest::certificate(
        prepared(
            &provider,
            ProviderOperation::CertificatePath,
            b"certificate",
        ),
        limits(1, 1),
    )
    .unwrap_or_else(|_| unreachable!());
    let mut effect = DeterministicProvider::begin_once(
        &provider,
        PendingBegin::Failed(ProviderFailureKind::Unavailable),
    );
    assert!(matches!(
        PendingOperation::begin(request, &mut effect),
        PendingStart::Failed(failure)
            if failure.kind()
                == PendingFailureKind::Provider(ProviderFailureKind::Unavailable)
    ));
    assert_eq!(effect.destroyed, 0);
}
