//! FIPS-aware provider architecture and permanent-failure tests.

mod support;

use brynja_core::{
    BackendFeatures, BackendIdentity, DestructionTargets, FipsBackendOwner, FipsBuildError,
    FipsBuildExpectations, FipsConfigurationError, FipsConfigurationField, FipsEnvironmentError,
    FipsModuleConfig, FipsModuleError, FipsModuleFault, FipsModuleSession, FipsModuleState,
    FipsOperationalEnvironment, FipsSelfTest, FipsSelfTestPlan, FipsSelfTestResult,
    FipsSelfTestRunner, FipsServiceDisposition, FipsServiceError, FipsServiceSet,
    FipsServiceSetError, FipsSspError, FipsSspFlow, FipsSspPolicy, ProviderOperation,
};

fn digest(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn build() -> FipsBuildExpectations {
    match FipsBuildExpectations::new(digest(1), digest(2), digest(3), digest(4)) {
        Ok(value) => value,
        Err(_) => unreachable!(),
    }
}

fn environment() -> FipsOperationalEnvironment {
    match FipsOperationalEnvironment::new(
        digest(5),
        BackendIdentity::Scalar,
        BackendFeatures::empty(),
        FipsBackendOwner::ModuleScalar,
    ) {
        Ok(value) => value,
        Err(_) => unreachable!(),
    }
}

fn set(operations: &[ProviderOperation]) -> FipsServiceSet {
    let mut builder = FipsServiceSet::builder();
    for operation in operations {
        builder = match builder.enable(*operation) {
            Ok(value) => value,
            Err(_) => unreachable!(),
        };
    }
    builder.freeze()
}

fn try_config<'provider>(
    provider: &'provider brynja_core::InstalledProvider,
    approved: FipsServiceSet,
    non_approved: FipsServiceSet,
) -> Result<FipsModuleConfig<'provider>, FipsConfigurationError> {
    let builder = FipsModuleConfig::builder(provider);
    let builder = builder.approved_services(approved)?;
    let builder = builder.non_approved_services(non_approved)?;
    let builder = builder.build(build())?;
    let builder = builder.environment(environment())?;
    let ssp = match FipsSspPolicy::new(FipsSspFlow::InternalOnly, DestructionTargets::all()) {
        Ok(value) => value,
        Err(_) => unreachable!(),
    };
    builder.ssp(ssp)?.freeze()
}

fn config(provider: &brynja_core::InstalledProvider) -> FipsModuleConfig<'_> {
    match try_config(
        provider,
        set(&[ProviderOperation::Hash]),
        FipsServiceSet::empty(),
    ) {
        Ok(value) => value,
        Err(_) => unreachable!(),
    }
}

struct Runner(FipsSelfTestResult);

impl FipsSelfTestRunner for Runner {
    fn run(&mut self, plan: FipsSelfTestPlan) -> FipsSelfTestResult {
        assert!(plan.contains(FipsSelfTest::ModuleIntegrity));
        assert!(plan.contains(FipsSelfTest::AlgorithmKnownAnswer));
        assert!(!plan.contains(FipsSelfTest::Conditional));
        self.0
    }
}

#[test]
fn service_sets_are_exact_and_may_be_empty() {
    assert!(FipsServiceSet::empty().is_empty());
    let one = set(&[ProviderOperation::AeadOpen]);
    assert_eq!(one.count(), 1);
    assert!(one.contains(ProviderOperation::AeadOpen));
    assert!(!one.contains(ProviderOperation::AeadSeal));
    let duplicate = FipsServiceSet::builder()
        .enable(ProviderOperation::Hash)
        .and_then(|builder| builder.enable(ProviderOperation::Hash));
    assert!(matches!(
        duplicate,
        Err(FipsServiceSetError::Duplicate(ProviderOperation::Hash))
    ));
}

#[test]
fn environment_build_and_ssp_assumptions_fail_closed() {
    assert!(matches!(
        FipsOperationalEnvironment::new(
            [0; 32],
            BackendIdentity::Scalar,
            BackendFeatures::empty(),
            FipsBackendOwner::ModuleScalar,
        ),
        Err(FipsEnvironmentError::EmptyIdentity)
    ));
    assert!(matches!(
        FipsOperationalEnvironment::new(
            digest(1),
            BackendIdentity::ValidatedModule,
            BackendFeatures::empty(),
            FipsBackendOwner::ModuleScalar,
        ),
        Err(FipsEnvironmentError::SealedProviderExcluded)
    ));
    assert!(matches!(
        FipsOperationalEnvironment::new(
            digest(1),
            BackendIdentity::X86Sha,
            BackendFeatures::empty(),
            FipsBackendOwner::ModuleAccelerated,
        ),
        Err(FipsEnvironmentError::BackendMismatch)
    ));
    assert!(matches!(
        FipsBuildExpectations::new(digest(1), [0; 32], digest(3), digest(4)),
        Err(FipsBuildError::EmptyDigest)
    ));
    assert!(matches!(
        FipsSspPolicy::new(
            FipsSspFlow::Import,
            DestructionTargets::new(false, false, false, false, false),
        ),
        Err(FipsSspError::EmptyDestructionTargets)
    ));
}

#[test]
fn configuration_is_complete_disjoint_and_provider_exact() {
    let provider = support::installed(
        ProviderOperation::Hash,
        DestructionTargets::all(),
        false,
        false,
    );
    let incomplete = FipsModuleConfig::builder(&provider).freeze();
    assert!(matches!(
        incomplete,
        Err(FipsConfigurationError::Incomplete(
            FipsConfigurationField::ApprovedServices
        ))
    ));

    assert!(matches!(
        try_config(
            &provider,
            set(&[ProviderOperation::Hash]),
            set(&[ProviderOperation::Hash])
        ),
        Err(FipsConfigurationError::ServiceOverlap(
            ProviderOperation::Hash
        ))
    ));
    assert!(matches!(
        try_config(&provider, FipsServiceSet::empty(), FipsServiceSet::empty()),
        Err(FipsConfigurationError::ServiceUnclassified(
            ProviderOperation::Hash
        ))
    ));
    assert!(matches!(
        try_config(
            &provider,
            set(&[ProviderOperation::Hash, ProviderOperation::AeadOpen]),
            FipsServiceSet::empty()
        ),
        Err(FipsConfigurationError::ServiceUnsupported(
            ProviderOperation::AeadOpen
        ))
    ));
    let duplicate = FipsModuleConfig::builder(&provider).approved_services(FipsServiceSet::empty());
    let Ok(duplicate) = duplicate else { return };
    assert!(matches!(
        duplicate.approved_services(FipsServiceSet::empty()),
        Err(FipsConfigurationError::Duplicate(
            FipsConfigurationField::ApprovedServices
        ))
    ));

    let frozen = config(&provider);
    assert_eq!(frozen.approved_services().count(), 1);
    assert!(frozen.non_approved_services().is_empty());
    assert_eq!(
        frozen.disposition(ProviderOperation::Hash),
        Some(FipsServiceDisposition::Approved)
    );
    assert_eq!(frozen.disposition(ProviderOperation::AeadOpen), None);
    assert_eq!(frozen.environment().identity(), &digest(5));
    assert_eq!(frozen.ssp_policy().flow(), FipsSspFlow::InternalOnly);
    assert_eq!(frozen.build_expectations(), &build());
    assert_eq!(frozen.build_expectations().source(), &digest(1));
    assert_eq!(frozen.build_expectations().toolchain(), &digest(2));
    assert_eq!(frozen.build_expectations().flags(), &digest(3));
    assert_eq!(frozen.build_expectations().dependencies(), &digest(4));

    let conditional = FipsModuleConfig::builder(&provider).require_conditional_self_tests();
    assert!(
        conditional
            .approved_services(set(&[ProviderOperation::Hash]))
            .and_then(|builder| builder.non_approved_services(FipsServiceSet::empty()))
            .and_then(|builder| builder.build(build()))
            .and_then(|builder| builder.environment(environment()))
            .and_then(|builder| builder.ssp(
                FipsSspPolicy::new(FipsSspFlow::InternalOnly, DestructionTargets::all())
                    .unwrap_or_else(|_| unreachable!())
            ))
            .and_then(|builder| builder.freeze())
            .map(|value| value.self_test_plan().contains(FipsSelfTest::Conditional))
            .unwrap_or(false)
    );
}

#[test]
fn self_tests_gate_services_and_failure_is_permanent() {
    let provider = support::installed(
        ProviderOperation::Hash,
        DestructionTargets::all(),
        false,
        false,
    );
    let config = config(&provider);
    let session = FipsModuleSession::new(&config);
    assert!(matches!(
        session.authorize(ProviderOperation::Hash),
        Err(FipsServiceError::NotOperational)
    ));
    assert!(
        session
            .run_self_tests(&mut Runner(FipsSelfTestResult::Passed))
            .is_ok()
    );
    let authorization = session.authorize(ProviderOperation::Hash);
    assert!(authorization.is_ok());
    let Ok(authorization) = authorization else {
        return;
    };
    assert_eq!(authorization.operation(), ProviderOperation::Hash);
    assert_eq!(
        authorization.disposition(),
        FipsServiceDisposition::Approved
    );
    assert!(authorization.is_current());
    assert!(matches!(
        session.authorize(ProviderOperation::AeadOpen),
        Err(FipsServiceError::Unsupported(ProviderOperation::AeadOpen))
    ));
    session.catastrophic_failure();
    assert!(!authorization.is_current());
    let snapshot = session.snapshot();
    assert_eq!(snapshot.state(), FipsModuleState::Failed);
    assert_eq!(snapshot.fault(), Some(FipsModuleFault::CatastrophicFailure));
}

#[test]
fn failed_or_interrupted_self_tests_never_recover() {
    let provider = support::installed(
        ProviderOperation::Hash,
        DestructionTargets::all(),
        false,
        false,
    );
    let config = config(&provider);
    let failed = FipsModuleSession::new(&config);
    assert_eq!(
        failed.run_self_tests(&mut Runner(FipsSelfTestResult::Failed)),
        Err(FipsModuleError::SelfTestFailed)
    );
    assert_eq!(
        failed.snapshot().fault(),
        Some(FipsModuleFault::SelfTestFailed)
    );
    assert_eq!(
        failed.run_self_tests(&mut Runner(FipsSelfTestResult::Passed)),
        Err(FipsModuleError::Failed)
    );

    struct PanicRunner(bool);
    impl FipsSelfTestRunner for PanicRunner {
        fn run(&mut self, _plan: FipsSelfTestPlan) -> FipsSelfTestResult {
            assert!(!self.0, "simulated interrupted self-test");
            FipsSelfTestResult::Passed
        }
    }
    let interrupted = FipsModuleSession::new(&config);
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = interrupted.run_self_tests(&mut PanicRunner(true));
    }));
    assert!(unwind.is_err());
    assert_eq!(
        interrupted.snapshot().fault(),
        Some(FipsModuleFault::SelfTestInterrupted)
    );
}

#[test]
fn self_test_reentry_permanently_fails_the_session() {
    let provider = support::installed(
        ProviderOperation::Hash,
        DestructionTargets::all(),
        false,
        false,
    );
    let config = config(&provider);
    let session = FipsModuleSession::new(&config);
    struct Reentrant<'a, 'config, 'provider>(&'a FipsModuleSession<'config, 'provider>);
    impl FipsSelfTestRunner for Reentrant<'_, '_, '_> {
        fn run(&mut self, _plan: FipsSelfTestPlan) -> FipsSelfTestResult {
            let nested = self
                .0
                .run_self_tests(&mut Runner(FipsSelfTestResult::Passed));
            assert_eq!(nested, Err(FipsModuleError::Reentrant));
            FipsSelfTestResult::Passed
        }
    }
    assert_eq!(
        session.run_self_tests(&mut Reentrant(&session)),
        Err(FipsModuleError::StateChanged)
    );
    assert_eq!(
        session.snapshot().fault(),
        Some(FipsModuleFault::ReentrantSelfTest)
    );
}
