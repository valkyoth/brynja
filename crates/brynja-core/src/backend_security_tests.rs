use core::cell::Cell;

use crate::{
    BackendDispatchError, BackendFault, BackendHealthState, BackendIdentity,
    BackendInitializationError, BackendKatFailure, BackendKatPass, BackendRuntimeGeneration,
    BackendServiceApproval, ProviderOperation,
    backend_execution::{
        BackendCpuContext, BackendCpuContextIdentity, BackendCpuGuard, BackendCpuIdentity,
        BackendCpuLease, BackendCpuRevalidationError, BackendKernel, BackendKernelPermit, sealed,
    },
    backend_session_tests::{initialize, profile, session_with_instance},
};

#[test]
fn kat_pass_and_failure_cannot_cross_equal_sessions() {
    let first = session_with_instance(BackendIdentity::X86Sha, &[ProviderOperation::Hash], 7, 9);
    let second = session_with_instance(BackendIdentity::X86Sha, &[ProviderOperation::Hash], 7, 9);
    let first_guard = first.begin_initialization();
    let second_guard = second.begin_initialization();
    assert!(first_guard.is_ok());
    assert!(second_guard.is_ok());
    if let (Ok(first_guard), Ok(second_guard)) = (first_guard, second_guard) {
        let snapshot = first.snapshot();
        let pass = BackendKatPass::for_test(
            &first,
            first.profile(),
            snapshot.runtime_generation(),
            snapshot.generation(),
            BackendServiceApproval::NotApplicable,
        );
        assert_eq!(
            second_guard.complete(pass).err(),
            Some(BackendInitializationError::EvidenceMismatch)
        );
        drop(first_guard);
    }
    assert_eq!(second.snapshot().state(), BackendHealthState::Quarantined);

    let first = session_with_instance(BackendIdentity::X86Sha, &[ProviderOperation::Hash], 11, 13);
    let second = session_with_instance(BackendIdentity::X86Sha, &[ProviderOperation::Hash], 11, 13);
    let first_guard = first.begin_initialization();
    let second_guard = second.begin_initialization();
    assert!(first_guard.is_ok());
    assert!(second_guard.is_ok());
    if let (Ok(first_guard), Ok(second_guard)) = (first_guard, second_guard) {
        let snapshot = first.snapshot();
        let failure = BackendKatFailure::for_test(
            &first,
            first.profile(),
            snapshot.runtime_generation(),
            snapshot.generation(),
            BackendFault::KnownAnswerFailed,
        );
        assert_eq!(
            second_guard.fail(failure).err(),
            Some(BackendInitializationError::EvidenceMismatch)
        );
        drop(first_guard);
    }
    assert_eq!(
        second.snapshot().fault(),
        Some(BackendFault::EvidenceMismatch)
    );
}

#[test]
fn validated_artifact_and_environment_substitution_fail_closed() {
    for (tested_artifact, tested_environment, target_artifact, target_environment) in
        [(1, 3, 2, 3), (5, 7, 5, 8)]
    {
        let tested = session_with_instance(
            BackendIdentity::ValidatedModule,
            &[ProviderOperation::Hash],
            tested_artifact,
            tested_environment,
        );
        let target = session_with_instance(
            BackendIdentity::ValidatedModule,
            &[ProviderOperation::Hash],
            target_artifact,
            target_environment,
        );
        assert!(!tested.instance().binding_matches(target.instance()));
        let guard = target.begin_initialization();
        assert!(guard.is_ok());
        if let Ok(guard) = guard {
            let pass = BackendKatPass::with_instance_for_test(
                &target,
                tested.instance(),
                BackendServiceApproval::Approved,
            );
            assert_eq!(
                guard.complete(pass).err(),
                Some(BackendInitializationError::EvidenceMismatch)
            );
        }
        assert_eq!(
            target.snapshot().fault(),
            Some(BackendFault::EvidenceMismatch)
        );
    }
}

struct MockCpuGuard<'context> {
    held: &'context Cell<bool>,
}

impl Drop for MockCpuGuard<'_> {
    fn drop(&mut self) {
        self.held.set(false);
    }
}

impl sealed::CpuGuard for MockCpuGuard<'_> {}
impl BackendCpuGuard for MockCpuGuard<'_> {}

struct MockCpuContext<'session> {
    identity: BackendCpuContextIdentity,
    cpu: Cell<BackendCpuIdentity>,
    features: Cell<crate::BackendFeatures>,
    migration_generation: Cell<u64>,
    operating_state_available: Cell<bool>,
    guard_held: Cell<bool>,
    invalidate_session: Option<&'session crate::BackendSession>,
}

impl sealed::CpuContext for MockCpuContext<'_> {}

impl BackendCpuContext for MockCpuContext<'_> {
    type Guard<'execution>
        = MockCpuGuard<'execution>
    where
        Self: 'execution;

    fn identity(&self) -> BackendCpuContextIdentity {
        self.identity
    }

    fn acquire_guard(
        &self,
        observed_cpu: BackendCpuIdentity,
        migration_generation: u64,
        backend_profile: crate::BackendProfile,
    ) -> Result<MockCpuGuard<'_>, BackendCpuRevalidationError> {
        if self.cpu.get() != observed_cpu {
            return Err(BackendCpuRevalidationError::CpuChanged);
        }
        if self.migration_generation.get() != migration_generation {
            return Err(BackendCpuRevalidationError::MigrationGenerationChanged);
        }
        if !self.operating_state_available.get() {
            return Err(BackendCpuRevalidationError::OperatingStateUnavailable);
        }
        if self.features.get() != backend_profile.features() {
            return Err(BackendCpuRevalidationError::FeaturesUnavailable);
        }
        self.guard_held.set(true);
        if let Some((session, next)) = self.invalidate_session.and_then(|session| {
            session
                .snapshot()
                .runtime_generation()
                .next()
                .ok()
                .map(|next| (session, next))
        }) {
            session.runtime_changed(next);
        }
        Ok(MockCpuGuard {
            held: &self.guard_held,
        })
    }
}

impl MockCpuContext<'_> {
    fn attempt_migration(&self, cpu: BackendCpuIdentity) -> bool {
        if self.guard_held.get() {
            false
        } else {
            self.cpu.set(cpu);
            true
        }
    }
}

struct MockKernel<'context, 'session> {
    context: &'context MockCpuContext<'session>,
    entries: &'context Cell<u8>,
    migration_target: BackendCpuIdentity,
}

impl sealed::Kernel for MockKernel<'_, '_> {}

impl BackendKernel for MockKernel<'_, '_> {
    type Output = (BackendIdentity, ProviderOperation, bool);

    fn execute(&self, permit: &BackendKernelPermit<'_>) -> Self::Output {
        self.entries.set(self.entries.get().saturating_add(1));
        (
            permit.identity(),
            permit.operation(),
            self.context.attempt_migration(self.migration_target),
        )
    }
}

#[test]
fn accelerated_entry_revalidates_cpu_migration_features_and_os_state() {
    let backend =
        session_with_instance(BackendIdentity::X86Avx2, &[ProviderOperation::Hash], 17, 19);
    let active = initialize(&backend, BackendServiceApproval::NotApplicable);
    assert!(active.is_ok());
    let Ok(active) = active else {
        return;
    };
    let dispatch =
        active.authorize_backend(ProviderOperation::Hash, BackendRuntimeGeneration::initial());
    assert!(dispatch.is_ok());
    let Ok(dispatch) = dispatch else {
        return;
    };
    let observed = BackendCpuIdentity::for_test([23; 32]);
    let context = MockCpuContext {
        identity: BackendCpuContextIdentity::for_test([21; 32]),
        cpu: Cell::new(observed),
        features: Cell::new(
            profile(BackendIdentity::X86Avx2, &[ProviderOperation::Hash]).features(),
        ),
        migration_generation: Cell::new(29),
        operating_state_available: Cell::new(true),
        guard_held: Cell::new(false),
        invalidate_session: None,
    };
    let lease = BackendCpuLease::for_test(
        &backend,
        context.identity(),
        observed,
        29,
        BackendRuntimeGeneration::initial(),
    );
    let entries = Cell::new(0_u8);
    let kernel = MockKernel {
        context: &context,
        entries: &entries,
        migration_target: BackendCpuIdentity::for_test([31; 32]),
    };
    let entered = dispatch.execute_kernel(
        BackendRuntimeGeneration::initial(),
        &lease,
        &context,
        &kernel,
    );
    assert_eq!(
        entered,
        Ok((BackendIdentity::X86Avx2, ProviderOperation::Hash, false))
    );
    assert!(!context.guard_held.get());
    assert!(context.cpu.get() == observed);

    context.cpu.set(BackendCpuIdentity::for_test([31; 32]));
    assert_eq!(
        dispatch
            .execute_kernel(
                BackendRuntimeGeneration::initial(),
                &lease,
                &context,
                &kernel,
            )
            .err(),
        Some(BackendDispatchError::CpuChanged)
    );
    context.cpu.set(observed);
    context.migration_generation.set(30);
    assert_eq!(
        dispatch
            .execute_kernel(
                BackendRuntimeGeneration::initial(),
                &lease,
                &context,
                &kernel,
            )
            .err(),
        Some(BackendDispatchError::CpuMigrationGenerationChanged)
    );
    context.migration_generation.set(29);
    context
        .features
        .set(BackendIdentity::X86Sha.required_features());
    assert_eq!(
        dispatch
            .execute_kernel(
                BackendRuntimeGeneration::initial(),
                &lease,
                &context,
                &kernel,
            )
            .err(),
        Some(BackendDispatchError::CpuFeaturesUnavailable)
    );
    context
        .features
        .set(BackendIdentity::X86Avx2.required_features());
    context.operating_state_available.set(false);
    assert_eq!(
        dispatch
            .execute_kernel(
                BackendRuntimeGeneration::initial(),
                &lease,
                &context,
                &kernel,
            )
            .err(),
        Some(BackendDispatchError::CpuOperatingStateUnavailable)
    );
    assert_eq!(entries.get(), 1);

    let reentrant =
        session_with_instance(BackendIdentity::X86Avx2, &[ProviderOperation::Hash], 53, 59);
    let active = initialize(&reentrant, BackendServiceApproval::NotApplicable);
    assert!(active.is_ok());
    let Ok(active) = active else {
        return;
    };
    let dispatch =
        active.authorize_backend(ProviderOperation::Hash, BackendRuntimeGeneration::initial());
    assert!(dispatch.is_ok());
    let Ok(dispatch) = dispatch else {
        return;
    };
    let reentrant_context = MockCpuContext {
        identity: BackendCpuContextIdentity::for_test([61; 32]),
        cpu: Cell::new(observed),
        features: Cell::new(BackendIdentity::X86Avx2.required_features()),
        migration_generation: Cell::new(67),
        operating_state_available: Cell::new(true),
        guard_held: Cell::new(false),
        invalidate_session: Some(&reentrant),
    };
    let lease = BackendCpuLease::for_test(
        &reentrant,
        reentrant_context.identity(),
        observed,
        67,
        BackendRuntimeGeneration::initial(),
    );
    let reentrant_entries = Cell::new(0_u8);
    let kernel = MockKernel {
        context: &reentrant_context,
        entries: &reentrant_entries,
        migration_target: BackendCpuIdentity::for_test([71; 32]),
    };
    assert_eq!(
        dispatch
            .execute_kernel(
                BackendRuntimeGeneration::initial(),
                &lease,
                &reentrant_context,
                &kernel,
            )
            .err(),
        Some(BackendDispatchError::RuntimeChanged)
    );
    assert_eq!(reentrant_entries.get(), 0);
    assert!(!reentrant_context.guard_held.get());
}

#[test]
fn cpu_lease_cannot_cross_equal_backend_sessions() {
    let first = session_with_instance(BackendIdentity::X86Sha, &[ProviderOperation::Hash], 37, 41);
    let second = session_with_instance(BackendIdentity::X86Sha, &[ProviderOperation::Hash], 37, 41);
    let active = initialize(&second, BackendServiceApproval::NotApplicable);
    assert!(active.is_ok());
    let Ok(active) = active else {
        return;
    };
    let dispatch =
        active.authorize_backend(ProviderOperation::Hash, BackendRuntimeGeneration::initial());
    assert!(dispatch.is_ok());
    let Ok(dispatch) = dispatch else {
        return;
    };
    let cpu = BackendCpuIdentity::for_test([43; 32]);
    let context = MockCpuContext {
        identity: BackendCpuContextIdentity::for_test([45; 32]),
        cpu: Cell::new(cpu),
        features: Cell::new(BackendIdentity::X86Sha.required_features()),
        migration_generation: Cell::new(47),
        operating_state_available: Cell::new(true),
        guard_held: Cell::new(false),
        invalidate_session: None,
    };
    let wrong_lease = BackendCpuLease::for_test(
        &first,
        context.identity(),
        cpu,
        47,
        BackendRuntimeGeneration::initial(),
    );
    let entries = Cell::new(0_u8);
    let kernel = MockKernel {
        context: &context,
        entries: &entries,
        migration_target: BackendCpuIdentity::for_test([49; 32]),
    };
    assert_eq!(
        dispatch
            .execute_kernel(
                BackendRuntimeGeneration::initial(),
                &wrong_lease,
                &context,
                &kernel,
            )
            .err(),
        Some(BackendDispatchError::CpuLeaseMismatch)
    );
    assert_eq!(entries.get(), 0);

    let correct_lease = BackendCpuLease::for_test(
        &second,
        context.identity(),
        cpu,
        47,
        BackendRuntimeGeneration::initial(),
    );
    let substituted_context = MockCpuContext {
        identity: BackendCpuContextIdentity::for_test([46; 32]),
        cpu: Cell::new(cpu),
        features: Cell::new(BackendIdentity::X86Sha.required_features()),
        migration_generation: Cell::new(47),
        operating_state_available: Cell::new(true),
        guard_held: Cell::new(false),
        invalidate_session: None,
    };
    let substituted_kernel = MockKernel {
        context: &substituted_context,
        entries: &entries,
        migration_target: BackendCpuIdentity::for_test([50; 32]),
    };
    assert_eq!(
        dispatch
            .execute_kernel(
                BackendRuntimeGeneration::initial(),
                &correct_lease,
                &substituted_context,
                &substituted_kernel,
            )
            .err(),
        Some(BackendDispatchError::CpuLeaseMismatch)
    );
    assert_eq!(entries.get(), 0);
}
