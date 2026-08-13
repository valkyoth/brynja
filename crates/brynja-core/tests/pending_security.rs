//! Adversarial pending-operation boundary tests.

mod support;

use std::panic::{AssertUnwindSafe, catch_unwind};

use brynja_core::{
    DestructionTargets, PendingDestructionCause, PendingDestructionFailureKind, PendingFailureKind,
    PendingOperation, PendingRequest, PendingStart, PendingTransition, ProviderOperation,
};
use support::{DeterministicProvider, Step, installed, limits, prepared};

#[test]
fn authorized_request_rejects_a_substituted_provider_before_effects() {
    let authorized = provider();
    let substituted = provider();
    let request = request(&authorized);
    let mut effect = DeterministicProvider::active(&substituted, &[], &[]);

    assert!(matches!(
        PendingOperation::begin(request, &mut effect),
        PendingStart::Failed(failure)
            if failure.kind() == PendingFailureKind::ProviderMismatch
    ));
    assert_eq!(effect.charged_units, 0);
    assert_eq!(effect.destroyed, 0);
}

#[test]
fn provider_derived_work_is_charged_before_each_effect() {
    let provider = provider();
    let mut effect = DeterministicProvider::active(&provider, &[Step::Complete], &[]);
    effect.step_cost = 20;
    let operation = active(request(&provider), &mut effect);

    assert!(matches!(
        operation.resume(),
        PendingTransition::Failed(failure)
            if failure.kind() == PendingFailureKind::WorkExhausted
    ));
    assert_eq!(effect.charged_units, 20);
    assert_eq!(effect.destroyed, 1);
    assert_eq!(effect.last_cause, Some(PendingDestructionCause::Exhaustion));
}

#[test]
fn zero_provider_charge_fails_before_an_effect() {
    let provider = provider();
    let mut effect = DeterministicProvider::active(&provider, &[], &[]);
    effect.step_cost = 0;

    assert!(matches!(
        PendingOperation::begin(request(&provider), &mut effect),
        PendingStart::Failed(failure)
            if failure.kind() == PendingFailureKind::InvalidWorkCharge
    ));
    assert_eq!(effect.charged_units, 0);
    assert_eq!(effect.destroyed, 0);
}

#[test]
fn unwind_during_resume_or_cancel_retains_state_for_drop_cleanup() {
    let provider = provider();
    let mut resume = DeterministicProvider::active(&provider, &[], &[]);
    resume.panic_resume = true;
    let operation = active(request(&provider), &mut resume);
    assert!(catch_unwind(AssertUnwindSafe(|| operation.resume())).is_err());
    assert_eq!(resume.destroyed, 1);
    assert_eq!(resume.last_cause, Some(PendingDestructionCause::Drop));

    let mut cancel = DeterministicProvider::active(&provider, &[], &[]);
    cancel.panic_cancel = true;
    let operation = active(request(&provider), &mut cancel);
    assert!(catch_unwind(AssertUnwindSafe(|| operation.cancel())).is_err());
    assert_eq!(cancel.destroyed, 1);
    assert_eq!(cancel.last_cause, Some(PendingDestructionCause::Drop));
}

#[test]
fn unwind_before_begin_resource_creation_cleans_inert_state() {
    let provider = provider();
    let mut effect = DeterministicProvider::active(&provider, &[], &[]);
    effect.panic_begin_before_external = true;

    assert!(begin_panics(&provider, &mut effect));
    assert_eq!(effect.external_resources, 0);
    assert_eq!(effect.destroyed, 1);
    assert_eq!(effect.last_destroyed_cursor, Some(0));
    assert_eq!(effect.last_cause, Some(PendingDestructionCause::Drop));
}

#[test]
fn unwind_after_begin_resource_creation_runs_authoritative_cleanup() {
    let provider = provider();
    let mut effect = DeterministicProvider::active(&provider, &[], &[]);
    effect.panic_begin_after_external = true;

    assert!(begin_panics(&provider, &mut effect));
    assert_eq!(effect.external_resources, 0);
    assert_eq!(effect.destroyed, 1);
    assert_eq!(effect.last_destroyed_cursor, Some(0));
    assert_eq!(effect.last_cause, Some(PendingDestructionCause::Drop));
}

#[test]
fn unwind_after_partial_begin_mutation_destroys_mutated_state() {
    let provider = provider();
    let mut effect = DeterministicProvider::active(&provider, &[], &[]);
    effect.panic_begin_after_mutation = true;

    assert!(begin_panics(&provider, &mut effect));
    assert_eq!(effect.external_resources, 0);
    assert_eq!(effect.destroyed, 1);
    assert_eq!(effect.last_destroyed_cursor, Some(1));
    assert_eq!(effect.last_cause, Some(PendingDestructionCause::Drop));
}

#[test]
fn begin_unwind_cleanup_failure_notifies_exactly_once() {
    let provider = provider();
    let mut effect = DeterministicProvider::active(&provider, &[], &[]);
    effect.panic_begin_after_external = true;
    effect.destroy_failure = Some(PendingDestructionFailureKind::AcceleratorHandle);

    assert!(begin_panics(&provider, &mut effect));
    assert_eq!(effect.external_resources, 1);
    assert_eq!(effect.destroyed, 1);
    assert_eq!(effect.drop_failures, 1);
    assert_eq!(effect.last_cause, Some(PendingDestructionCause::Drop));
}

fn provider() -> brynja_core::InstalledProvider {
    installed(
        ProviderOperation::Hash,
        DestructionTargets::all(),
        true,
        true,
    )
}

fn request<'provider>(
    provider: &'provider brynja_core::InstalledProvider,
) -> PendingRequest<'provider, 'static> {
    PendingRequest::accelerator(
        prepared(provider, ProviderOperation::Hash, b"input"),
        limits(2, 1),
    )
    .unwrap_or_else(|_| unreachable!())
}

fn active<'provider, 'effect>(
    request: PendingRequest<'provider, 'static>,
    effect: &'effect mut DeterministicProvider<'provider>,
) -> brynja_core::PendingOperation<'provider, 'static, 'effect, DeterministicProvider<'provider>> {
    match PendingOperation::begin(request, effect) {
        PendingStart::Active(operation) => operation,
        _ => unreachable!(),
    }
}

fn begin_panics(
    provider: &brynja_core::InstalledProvider,
    effect: &mut DeterministicProvider<'_>,
) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        let _start = PendingOperation::begin(request(provider), effect);
    }))
    .is_err()
}
