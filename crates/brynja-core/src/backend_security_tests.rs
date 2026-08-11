use core::cell::Cell;

use crate::{
    BackendDispatchError, BackendFault, BackendHealthState, BackendIdentity,
    BackendInitializationError, BackendKatFailure, BackendKatPass, BackendRuntimeGeneration,
    BackendServiceApproval, ProviderOperation,
    backend_execution::{
        BackendCpuContext, BackendCpuIdentity, BackendCpuLease, BackendCpuRevalidationError,
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

struct MockCpuContext {
    cpu: Cell<BackendCpuIdentity>,
    features: Cell<crate::BackendFeatures>,
    migration_generation: Cell<u64>,
    operating_state_available: Cell<bool>,
}

impl BackendCpuContext for MockCpuContext {
    fn revalidate(
        &self,
        observed_cpu: BackendCpuIdentity,
        migration_generation: u64,
        backend_profile: crate::BackendProfile,
    ) -> Result<(), BackendCpuRevalidationError> {
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
        Ok(())
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
        cpu: Cell::new(observed),
        features: Cell::new(
            profile(BackendIdentity::X86Avx2, &[ProviderOperation::Hash]).features(),
        ),
        migration_generation: Cell::new(29),
        operating_state_available: Cell::new(true),
    };
    let lease = BackendCpuLease::for_test(
        &context,
        &backend,
        observed,
        29,
        BackendRuntimeGeneration::initial(),
    );
    let entries = Cell::new(0_u8);
    let entered = dispatch.enter_kernel(BackendRuntimeGeneration::initial(), &lease, |permit| {
        entries.set(entries.get().saturating_add(1));
        (permit.identity(), permit.operation())
    });
    assert_eq!(
        entered,
        Ok((BackendIdentity::X86Avx2, ProviderOperation::Hash))
    );

    context.cpu.set(BackendCpuIdentity::for_test([31; 32]));
    assert_eq!(
        dispatch
            .enter_kernel(BackendRuntimeGeneration::initial(), &lease, |_| ())
            .err(),
        Some(BackendDispatchError::CpuChanged)
    );
    context.cpu.set(observed);
    context.migration_generation.set(30);
    assert_eq!(
        dispatch
            .enter_kernel(BackendRuntimeGeneration::initial(), &lease, |_| ())
            .err(),
        Some(BackendDispatchError::CpuMigrationGenerationChanged)
    );
    context.migration_generation.set(29);
    context
        .features
        .set(BackendIdentity::X86Sha.required_features());
    assert_eq!(
        dispatch
            .enter_kernel(BackendRuntimeGeneration::initial(), &lease, |_| ())
            .err(),
        Some(BackendDispatchError::CpuFeaturesUnavailable)
    );
    context
        .features
        .set(BackendIdentity::X86Avx2.required_features());
    context.operating_state_available.set(false);
    assert_eq!(
        dispatch
            .enter_kernel(BackendRuntimeGeneration::initial(), &lease, |_| ())
            .err(),
        Some(BackendDispatchError::CpuOperatingStateUnavailable)
    );
    assert_eq!(entries.get(), 1);
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
        cpu: Cell::new(cpu),
        features: Cell::new(BackendIdentity::X86Sha.required_features()),
        migration_generation: Cell::new(47),
        operating_state_available: Cell::new(true),
    };
    let wrong_lease = BackendCpuLease::for_test(
        &context,
        &first,
        cpu,
        47,
        BackendRuntimeGeneration::initial(),
    );
    assert_eq!(
        dispatch
            .enter_kernel(BackendRuntimeGeneration::initial(), &wrong_lease, |_| ())
            .err(),
        Some(BackendDispatchError::CpuLeaseMismatch)
    );
}
