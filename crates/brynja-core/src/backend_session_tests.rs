use crate::{
    ActiveBackend, BackendCandidate, BackendDispatchError, BackendEvidenceOrigin,
    BackendFallbackReason, BackendFault, BackendFeature, BackendFeatures, BackendHealthState,
    BackendIdentity, BackendInitializationError, BackendInstanceIdentity, BackendKatFailure,
    BackendKatPass, BackendPolicy, BackendProfile, BackendRuntimeGeneration,
    BackendServiceApproval, BackendSession, ProviderCapabilities, ProviderCapabilitiesBuilder,
    ProviderOperation, select_backend,
};

fn capabilities(operations: &[ProviderOperation]) -> ProviderCapabilities {
    let mut builder = ProviderCapabilities::builder();
    for operation in operations {
        let result = builder.enable(*operation);
        assert!(result.is_ok());
        let Ok(next) = result else {
            return one_capability();
        };
        builder = next;
    }
    let frozen = builder.freeze();
    assert!(frozen.is_ok());
    match frozen {
        Ok(value) => value,
        Err(_) => one_capability(),
    }
}

fn one_capability() -> ProviderCapabilities {
    let result = ProviderCapabilitiesBuilder::EMPTY
        .enable(ProviderOperation::Hash)
        .and_then(ProviderCapabilitiesBuilder::freeze);
    match result {
        Ok(value) => value,
        Err(_) => {
            let retry = ProviderCapabilities::builder()
                .enable(ProviderOperation::Hash)
                .and_then(ProviderCapabilitiesBuilder::freeze);
            match retry {
                Ok(value) => value,
                Err(_) => unreachable_capabilities(),
            }
        }
    }
}

fn unreachable_capabilities() -> ProviderCapabilities {
    let builder = ProviderCapabilities::builder();
    let Ok(builder) = builder.enable(ProviderOperation::Hash) else {
        return capabilities(&[ProviderOperation::Hash]);
    };
    let Ok(value) = builder.freeze() else {
        return capabilities(&[ProviderOperation::Hash]);
    };
    value
}

pub(crate) fn profile(
    identity: BackendIdentity,
    operations: &[ProviderOperation],
) -> BackendProfile {
    let result = BackendProfile::new(
        identity,
        identity.required_features(),
        capabilities(operations),
    );
    assert!(result.is_ok());
    match result {
        Ok(value) => value,
        Err(_) => {
            let fallback = BackendProfile::new(
                BackendIdentity::Scalar,
                BackendFeatures::empty(),
                one_capability(),
            );
            match fallback {
                Ok(value) => value,
                Err(_) => profile(BackendIdentity::Scalar, &[ProviderOperation::Hash]),
            }
        }
    }
}

fn session(identity: BackendIdentity, operations: &[ProviderOperation]) -> BackendSession {
    session_with_instance(identity, operations, 1, 1)
}

pub(crate) fn session_with_instance(
    identity: BackendIdentity,
    operations: &[ProviderOperation],
    artifact: u8,
    environment: u8,
) -> BackendSession {
    let evidence = crate::BackendFeatureEvidence::for_test(
        profile(identity, operations),
        BackendEvidenceOrigin::PlatformObserved,
        BackendInstanceIdentity::for_test([artifact; 32], [environment; 32]),
    );
    let candidate = BackendCandidate::from_evidence(evidence);
    BackendSession::from_candidate(candidate, BackendRuntimeGeneration::initial())
}

pub(crate) fn initialize(
    session: &BackendSession,
    approval: BackendServiceApproval,
) -> Result<ActiveBackend<'_>, BackendInitializationError> {
    let initialization = session.begin_initialization()?;
    let snapshot = session.snapshot();
    let pass = BackendKatPass::for_test(
        session,
        session.profile(),
        snapshot.runtime_generation(),
        snapshot.generation(),
        approval,
    );
    initialization.complete(pass)
}

#[test]
fn exact_feature_bundles_are_sealed_and_single_assignment() {
    for identity in [
        BackendIdentity::Scalar,
        BackendIdentity::X86Sha,
        BackendIdentity::X86AesGcm,
        BackendIdentity::X86Avx2,
        BackendIdentity::X86Avx512,
        BackendIdentity::Aarch64Sha2,
        BackendIdentity::Aarch64AesGcm,
        BackendIdentity::RiscVVector,
        BackendIdentity::RiscVScalarCrypto,
        BackendIdentity::ValidatedModule,
    ] {
        let exact = BackendProfile::new(
            identity,
            identity.required_features(),
            capabilities(&[ProviderOperation::Hash]),
        );
        assert!(exact.is_ok());
    }

    let duplicate = BackendFeatures::builder()
        .enable(BackendFeature::X86Sha)
        .and_then(|builder| builder.enable(BackendFeature::X86Sha));
    assert!(duplicate.is_err());
    let mismatch = BackendProfile::new(
        BackendIdentity::X86Sha,
        BackendFeatures::empty(),
        capabilities(&[ProviderOperation::Hash]),
    );
    assert!(mismatch.is_err());
}

#[test]
fn successful_kat_binds_health_runtime_operation_and_report() {
    let scalar = session(
        BackendIdentity::Scalar,
        &[ProviderOperation::Hash, ProviderOperation::MacGenerate],
    );
    let active = initialize(&scalar, BackendServiceApproval::NotApplicable);
    assert!(active.is_ok());
    let Ok(active) = active else {
        return;
    };
    let snapshot = active.snapshot();
    assert_eq!(snapshot.state(), BackendHealthState::Healthy);
    assert_eq!(snapshot.generation(), 3);

    let dispatch = select_backend(
        BackendPolicy::ScalarOnly,
        ProviderOperation::Hash,
        BackendRuntimeGeneration::initial(),
        None,
        &active,
    );
    assert!(dispatch.is_ok());
    let Ok(dispatch) = dispatch else {
        return;
    };
    assert_eq!(dispatch.operation(), ProviderOperation::Hash);
    assert!(
        dispatch
            .validate(BackendRuntimeGeneration::initial())
            .is_ok()
    );
    assert_eq!(
        dispatch.report().reason(),
        crate::BackendSelectionReason::ScalarRequired
    );
}

#[test]
fn interruption_and_explicit_failure_quarantine_permanently() {
    let interrupted = session(BackendIdentity::X86Sha, &[ProviderOperation::Hash]);
    {
        let guard = interrupted.begin_initialization();
        assert!(guard.is_ok());
    }
    assert_eq!(
        interrupted.snapshot().fault(),
        Some(BackendFault::InitializationInterrupted)
    );
    assert!(interrupted.begin_initialization().is_err());
    let next = BackendRuntimeGeneration::initial().next();
    assert!(next.is_ok());
    if let Ok(next) = next {
        interrupted.runtime_changed(next);
    }
    assert_eq!(
        interrupted.snapshot().state(),
        BackendHealthState::Quarantined
    );

    let failed = session(BackendIdentity::X86Sha, &[ProviderOperation::Hash]);
    let guard = failed.begin_initialization();
    assert!(guard.is_ok());
    if let Ok(guard) = guard {
        let snapshot = failed.snapshot();
        let evidence = BackendKatFailure::for_test(
            &failed,
            failed.profile(),
            snapshot.runtime_generation(),
            snapshot.generation(),
            BackendFault::KnownAnswerFailed,
        );
        assert!(guard.fail(evidence).is_ok());
    }
    assert_eq!(
        failed.snapshot().fault(),
        Some(BackendFault::KnownAnswerFailed)
    );
}

#[test]
fn recursion_quarantines_and_cannot_be_completed_by_outer_guard() {
    let backend = session(BackendIdentity::X86Sha, &[ProviderOperation::Hash]);
    let outer = backend.begin_initialization();
    assert!(outer.is_ok());
    let recursive = backend.begin_initialization();
    assert_eq!(recursive.err(), Some(BackendInitializationError::Reentrant));
    assert_eq!(
        backend.snapshot().fault(),
        Some(BackendFault::ReentrantInitialization)
    );
    if let Ok(outer) = outer {
        let snapshot = backend.snapshot();
        let pass = BackendKatPass::for_test(
            &backend,
            backend.profile(),
            snapshot.runtime_generation(),
            snapshot.generation(),
            BackendServiceApproval::NotApplicable,
        );
        assert!(outer.complete(pass).is_err());
    }
    assert_eq!(backend.snapshot().state(), BackendHealthState::Quarantined);
}

#[test]
fn mismatched_evidence_and_approval_fail_closed() {
    let mismatch = session(BackendIdentity::X86Sha, &[ProviderOperation::Hash]);
    let guard = mismatch.begin_initialization();
    assert!(guard.is_ok());
    if let Ok(guard) = guard {
        let snapshot = mismatch.snapshot();
        let wrong = BackendKatPass::for_test(
            &mismatch,
            profile(BackendIdentity::X86Avx2, &[ProviderOperation::Hash]),
            snapshot.runtime_generation(),
            snapshot.generation(),
            BackendServiceApproval::NotApplicable,
        );
        assert_eq!(
            guard.complete(wrong).err(),
            Some(BackendInitializationError::EvidenceMismatch)
        );
    }
    assert_eq!(
        mismatch.snapshot().fault(),
        Some(BackendFault::EvidenceMismatch)
    );

    let scalar = session(BackendIdentity::Scalar, &[ProviderOperation::Hash]);
    assert_eq!(
        initialize(&scalar, BackendServiceApproval::Approved).err(),
        Some(BackendInitializationError::ApprovalMismatch)
    );
    let validated = session(BackendIdentity::ValidatedModule, &[ProviderOperation::Hash]);
    assert_eq!(
        initialize(&validated, BackendServiceApproval::NotApplicable).err(),
        Some(BackendInitializationError::ApprovalMismatch)
    );
}

#[test]
fn policies_are_exact_and_only_opportunistic_mode_falls_back() {
    let scalar = session(BackendIdentity::Scalar, &[ProviderOperation::Hash]);
    let scalar_active = initialize(&scalar, BackendServiceApproval::NotApplicable);
    assert!(scalar_active.is_ok());
    let Ok(scalar_active) = scalar_active else {
        return;
    };

    let fallback = select_backend(
        BackendPolicy::Opportunistic,
        ProviderOperation::Hash,
        BackendRuntimeGeneration::initial(),
        None,
        &scalar_active,
    );
    assert!(fallback.is_ok());
    if let Ok(fallback) = fallback {
        assert_eq!(
            fallback.report().reason(),
            crate::BackendSelectionReason::ScalarFallback(
                BackendFallbackReason::CandidateUnavailable
            )
        );
    }
    assert_eq!(
        select_backend(
            BackendPolicy::RequiredAccelerated,
            ProviderOperation::Hash,
            BackendRuntimeGeneration::initial(),
            None,
            &scalar_active,
        )
        .err(),
        Some(BackendDispatchError::Unavailable)
    );
    assert_eq!(
        select_backend(
            BackendPolicy::ValidatedModuleOnly,
            ProviderOperation::Hash,
            BackendRuntimeGeneration::initial(),
            Some(&scalar_active),
            &scalar_active,
        )
        .err(),
        Some(BackendDispatchError::BackendClassMismatch)
    );
}

#[test]
fn required_and_validated_modes_never_substitute_scalar() {
    let scalar = session(BackendIdentity::Scalar, &[ProviderOperation::Hash]);
    let scalar_active = initialize(&scalar, BackendServiceApproval::NotApplicable);
    let accelerated = session(BackendIdentity::X86Sha, &[ProviderOperation::Hash]);
    let accelerated_active = initialize(&accelerated, BackendServiceApproval::NotApplicable);
    let validated = session(BackendIdentity::ValidatedModule, &[ProviderOperation::Hash]);
    let validated_active = initialize(&validated, BackendServiceApproval::Approved);
    assert!(scalar_active.is_ok());
    assert!(accelerated_active.is_ok());
    assert!(validated_active.is_ok());
    let (Ok(scalar_active), Ok(accelerated_active), Ok(validated_active)) =
        (scalar_active, accelerated_active, validated_active)
    else {
        return;
    };

    assert!(
        select_backend(
            BackendPolicy::RequiredAccelerated,
            ProviderOperation::Hash,
            BackendRuntimeGeneration::initial(),
            Some(&accelerated_active),
            &scalar_active,
        )
        .is_ok()
    );
    let approved = select_backend(
        BackendPolicy::ValidatedModuleOnly,
        ProviderOperation::Hash,
        BackendRuntimeGeneration::initial(),
        Some(&validated_active),
        &scalar_active,
    );
    assert!(approved.is_ok());
    if let Ok(approved) = approved {
        assert_eq!(
            approved.report().service_approval(),
            BackendServiceApproval::Approved
        );
    }
    assert_eq!(
        select_backend(
            BackendPolicy::ValidatedModuleOnly,
            ProviderOperation::Hash,
            BackendRuntimeGeneration::initial(),
            Some(&accelerated_active),
            &scalar_active,
        )
        .err(),
        Some(BackendDispatchError::BackendClassMismatch)
    );
}

#[test]
fn quarantine_and_runtime_changes_invalidate_existing_authority() {
    let scalar = session(BackendIdentity::Scalar, &[ProviderOperation::Hash]);
    let active = initialize(&scalar, BackendServiceApproval::NotApplicable);
    assert!(active.is_ok());
    let Ok(active) = active else {
        return;
    };
    let dispatch =
        active.authorize_backend(ProviderOperation::Hash, BackendRuntimeGeneration::initial());
    assert!(dispatch.is_ok());
    scalar.quarantine(BackendFault::KnownAnswerFailed);
    if let Ok(dispatch) = dispatch {
        assert_eq!(
            dispatch.validate(BackendRuntimeGeneration::initial()).err(),
            Some(BackendDispatchError::Quarantined)
        );
    }

    let cloned = session(BackendIdentity::Scalar, &[ProviderOperation::Hash]);
    let active = initialize(&cloned, BackendServiceApproval::NotApplicable);
    assert!(active.is_ok());
    let Ok(active) = active else {
        return;
    };
    let next = BackendRuntimeGeneration::initial().next();
    assert!(next.is_ok());
    if let Ok(next) = next {
        cloned.runtime_changed(next);
        assert_eq!(
            active
                .authorize_backend(ProviderOperation::Hash, next)
                .err(),
            Some(BackendDispatchError::RuntimeChanged)
        );
        assert_eq!(cloned.snapshot().state(), BackendHealthState::NeverTested);
    }
}

#[test]
fn operation_authority_is_exact_and_reports_are_not_tokens() {
    let scalar = session(BackendIdentity::Scalar, &[ProviderOperation::Hash]);
    let active = initialize(&scalar, BackendServiceApproval::NotApplicable);
    assert!(active.is_ok());
    let Ok(active) = active else {
        return;
    };
    assert_eq!(
        active
            .authorize_backend(
                ProviderOperation::AeadSeal,
                BackendRuntimeGeneration::initial(),
            )
            .err(),
        Some(BackendDispatchError::UnsupportedOperation)
    );
    let dispatch =
        active.authorize_backend(ProviderOperation::Hash, BackendRuntimeGeneration::initial());
    assert!(dispatch.is_ok());
    if let Ok(dispatch) = dispatch {
        let report = dispatch.report();
        assert_eq!(report.operation(), ProviderOperation::Hash);
        assert_eq!(report.identity(), BackendIdentity::Scalar);
        assert_eq!(report.policy(), BackendPolicy::ScalarOnly);
    }
}
