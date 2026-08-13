//! Inert FIPS-aware provider, build, environment, service, and SSP boundaries.

use crate::{
    BackendClass, BackendFeatures, BackendIdentity, DestructionTargets, FipsBuildExpectations,
    FipsServiceSet, InstalledProvider, ProviderOperation,
};

/// Policy classification for one future module service.
///
/// `Approved` is reserved for a later exact algorithm-and-parameter identity.
/// The current operation-category model rejects every nonempty approved set.
/// Neither variant grants provider or backend execution authority.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum FipsServiceDisposition {
    /// Intended for an approved service after applicable validation.
    Approved,
    /// Intentionally available only as a non-approved service.
    NonApproved,
}

/// Ownership of one future module implementation backend.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum FipsBackendOwner {
    /// The module owns the portable scalar symbol.
    ModuleScalar,
    /// The module owns one exact ISA-specific symbol.
    ModuleAccelerated,
}

/// A closed operational-environment construction failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum FipsEnvironmentError {
    /// The environment identifier was the reserved all-zero value.
    EmptyIdentity,
    /// The ordinary sealed-provider placeholder cannot enter this boundary.
    SealedProviderExcluded,
    /// Backend class, owner, or feature assumptions disagreed.
    BackendMismatch,
}

/// Immutable assumptions for one future operational environment.
///
/// This is not measured runtime evidence and cannot authorize an instruction.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct FipsOperationalEnvironment {
    identity: [u8; 32],
    backend: BackendIdentity,
    features: BackendFeatures,
    owner: FipsBackendOwner,
}

impl FipsOperationalEnvironment {
    /// Freezes exact environment, backend, feature, and ownership assumptions.
    pub fn new(
        identity: [u8; 32],
        backend: BackendIdentity,
        features: BackendFeatures,
        owner: FipsBackendOwner,
    ) -> Result<Self, FipsEnvironmentError> {
        if identity == [0; 32] {
            return Err(FipsEnvironmentError::EmptyIdentity);
        }
        if matches!(backend, BackendIdentity::ValidatedModule) {
            return Err(FipsEnvironmentError::SealedProviderExcluded);
        }
        let owner_matches = match owner {
            FipsBackendOwner::ModuleScalar => matches!(backend, BackendIdentity::Scalar),
            FipsBackendOwner::ModuleAccelerated => {
                matches!(backend.class(), BackendClass::Accelerated)
            }
        };
        if !owner_matches || features != backend.required_features() {
            Err(FipsEnvironmentError::BackendMismatch)
        } else {
            Ok(Self {
                identity,
                backend,
                features,
                owner,
            })
        }
    }

    /// Returns the sealed implementation backend.
    #[must_use]
    pub const fn backend(&self) -> BackendIdentity {
        self.backend
    }

    /// Returns the exact assumed feature bundle.
    #[must_use]
    pub const fn features(&self) -> BackendFeatures {
        self.features
    }

    /// Returns the module-owned symbol class.
    #[must_use]
    pub const fn owner(&self) -> FipsBackendOwner {
        self.owner
    }

    /// Returns the exact expected operational-environment identity.
    #[must_use]
    pub const fn identity(&self) -> &[u8; 32] {
        &self.identity
    }
}

/// Permitted SSP movement across a future module port.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum FipsSspFlow {
    /// SSP values may only exist inside the module boundary.
    InternalOnly,
    /// A controlled input port may import an SSP.
    Import,
    /// A controlled output port may export an SSP.
    Export,
    /// Separate controlled ports may import and export SSPs.
    ImportAndExport,
}

/// Frozen SSP port and complete-copy destruction expectations.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct FipsSspPolicy {
    flow: FipsSspFlow,
    destruction_targets: DestructionTargets,
}

impl FipsSspPolicy {
    const fn from_provider(flow: FipsSspFlow, destruction_targets: DestructionTargets) -> Self {
        Self {
            flow,
            destruction_targets,
        }
    }

    /// Returns the only admitted SSP movement policy.
    #[must_use]
    pub const fn flow(self) -> FipsSspFlow {
        self.flow
    }

    /// Returns every mandatory SSP destruction location.
    #[must_use]
    pub const fn destruction_targets(self) -> DestructionTargets {
        self.destruction_targets
    }
}

/// One exact self-test category required before service use.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum FipsSelfTest {
    /// Cryptographic module integrity test.
    ModuleIntegrity,
    /// Algorithm known-answer tests.
    AlgorithmKnownAnswer,
    /// Conditional tests required by enabled services.
    Conditional,
}

impl FipsSelfTest {
    const fn mask(self) -> u8 {
        match self {
            Self::ModuleIntegrity => 1,
            Self::AlgorithmKnownAnswer => 2,
            Self::Conditional => 4,
        }
    }
}

/// Exact nonempty self-test plan required by one configuration.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FipsSelfTestPlan(u8);

impl FipsSelfTestPlan {
    /// Freezes the mandatory integrity and algorithm KAT baseline.
    #[must_use]
    pub const fn mandatory() -> Self {
        Self(FipsSelfTest::ModuleIntegrity.mask() | FipsSelfTest::AlgorithmKnownAnswer.mask())
    }

    /// Adds one exact conditional test category.
    #[must_use]
    pub const fn require(mut self, test: FipsSelfTest) -> Self {
        self.0 |= test.mask();
        self
    }

    /// Reports whether one category is required.
    #[must_use]
    pub const fn contains(self, test: FipsSelfTest) -> bool {
        self.0 & test.mask() != 0
    }
}

/// Mandatory module configuration field.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum FipsConfigurationField {
    /// Exact services intended to be approved.
    ApprovedServices,
    /// Exact services intentionally non-approved.
    NonApprovedServices,
    /// Deterministic build expectations.
    Build,
    /// Exact operational-environment assumptions.
    Environment,
    /// SSP port and destruction policy.
    Ssp,
}

/// Closed module-configuration failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum FipsConfigurationError {
    /// A mandatory field was assigned twice.
    Duplicate(FipsConfigurationField),
    /// A mandatory field was not assigned.
    Incomplete(FipsConfigurationField),
    /// One operation appeared in both service sets.
    ServiceOverlap(ProviderOperation),
    /// A provider operation had no classification.
    ServiceUnclassified(ProviderOperation),
    /// A classified service was absent from the provider contract.
    ServiceUnsupported(ProviderOperation),
    /// Operation categories are not exact enough to identify approved services.
    ApprovedServicesRequireExactIdentity,
}

/// Transactional builder for one inert future module configuration.
#[must_use = "the FIPS-aware module configuration must be completed"]
pub struct FipsModuleBuilder<'provider> {
    provider: &'provider InstalledProvider,
    approved: Option<FipsServiceSet>,
    non_approved: Option<FipsServiceSet>,
    build: Option<FipsBuildExpectations>,
    environment: Option<FipsOperationalEnvironment>,
    ssp_flow: Option<FipsSspFlow>,
    self_tests: FipsSelfTestPlan,
}

/// Frozen FIPS-aware policy boundary with no executable provider or claim.
pub struct FipsModuleConfig<'provider> {
    provider: &'provider InstalledProvider,
    approved: FipsServiceSet,
    non_approved: FipsServiceSet,
    build: FipsBuildExpectations,
    environment: FipsOperationalEnvironment,
    ssp: FipsSspPolicy,
    self_tests: FipsSelfTestPlan,
}

impl<'provider> FipsModuleConfig<'provider> {
    /// Starts a configuration around one exact installed provider contract.
    pub const fn builder(provider: &'provider InstalledProvider) -> FipsModuleBuilder<'provider> {
        FipsModuleBuilder {
            provider,
            approved: None,
            non_approved: None,
            build: None,
            environment: None,
            ssp_flow: None,
            self_tests: FipsSelfTestPlan::mandatory(),
        }
    }

    /// Returns one exact service's policy classification.
    #[must_use]
    pub const fn disposition(
        &self,
        operation: ProviderOperation,
    ) -> Option<FipsServiceDisposition> {
        if self.approved.contains(operation) {
            Some(FipsServiceDisposition::Approved)
        } else if self.non_approved.contains(operation) {
            Some(FipsServiceDisposition::NonApproved)
        } else {
            None
        }
    }

    /// Returns the reserved approved-category set, currently always empty.
    #[must_use]
    pub const fn approved_services(&self) -> FipsServiceSet {
        self.approved
    }

    /// Returns the complete explicitly non-approved operation categories.
    #[must_use]
    pub const fn non_approved_services(&self) -> FipsServiceSet {
        self.non_approved
    }

    /// Returns exact operational-environment assumptions.
    #[must_use]
    pub const fn environment(&self) -> &FipsOperationalEnvironment {
        &self.environment
    }

    /// Returns the frozen SSP policy.
    #[must_use]
    pub const fn ssp_policy(&self) -> FipsSspPolicy {
        self.ssp
    }

    /// Returns the exact required self-test plan.
    #[must_use]
    pub const fn self_test_plan(&self) -> FipsSelfTestPlan {
        self.self_tests
    }

    pub(crate) const fn provider(&self) -> &'provider InstalledProvider {
        self.provider
    }

    /// Returns deterministic module-build expectations.
    #[must_use]
    pub const fn build_expectations(&self) -> &FipsBuildExpectations {
        &self.build
    }
}

impl<'provider> FipsModuleBuilder<'provider> {
    /// Assigns reserved approval intent; any nonempty set fails at freeze.
    pub const fn approved_services(
        mut self,
        value: FipsServiceSet,
    ) -> Result<Self, FipsConfigurationError> {
        if self.approved.is_some() {
            Err(FipsConfigurationError::Duplicate(
                FipsConfigurationField::ApprovedServices,
            ))
        } else {
            self.approved = Some(value);
            Ok(self)
        }
    }

    /// Assigns explicitly non-approved operation categories.
    pub const fn non_approved_services(
        mut self,
        value: FipsServiceSet,
    ) -> Result<Self, FipsConfigurationError> {
        if self.non_approved.is_some() {
            Err(FipsConfigurationError::Duplicate(
                FipsConfigurationField::NonApprovedServices,
            ))
        } else {
            self.non_approved = Some(value);
            Ok(self)
        }
    }

    /// Assigns deterministic module-build expectations.
    pub const fn build(
        mut self,
        value: FipsBuildExpectations,
    ) -> Result<Self, FipsConfigurationError> {
        if self.build.is_some() {
            Err(FipsConfigurationError::Duplicate(
                FipsConfigurationField::Build,
            ))
        } else {
            self.build = Some(value);
            Ok(self)
        }
    }

    /// Assigns exact operational-environment assumptions.
    pub const fn environment(
        mut self,
        value: FipsOperationalEnvironment,
    ) -> Result<Self, FipsConfigurationError> {
        if self.environment.is_some() {
            Err(FipsConfigurationError::Duplicate(
                FipsConfigurationField::Environment,
            ))
        } else {
            self.environment = Some(value);
            Ok(self)
        }
    }

    /// Assigns SSP port flow; destruction duties come from the provider.
    pub const fn ssp_flow(mut self, value: FipsSspFlow) -> Result<Self, FipsConfigurationError> {
        if self.ssp_flow.is_some() {
            Err(FipsConfigurationError::Duplicate(
                FipsConfigurationField::Ssp,
            ))
        } else {
            self.ssp_flow = Some(value);
            Ok(self)
        }
    }

    /// Requires conditional tests in addition to the mandatory baseline.
    pub const fn require_conditional_self_tests(mut self) -> Self {
        self.self_tests = self.self_tests.require(FipsSelfTest::Conditional);
        self
    }

    /// Validates complete, disjoint service classification and freezes policy.
    pub fn freeze(self) -> Result<FipsModuleConfig<'provider>, FipsConfigurationError> {
        let approved = self.approved.ok_or(FipsConfigurationError::Incomplete(
            FipsConfigurationField::ApprovedServices,
        ))?;
        let non_approved = self.non_approved.ok_or(FipsConfigurationError::Incomplete(
            FipsConfigurationField::NonApprovedServices,
        ))?;
        let build = self.build.ok_or(FipsConfigurationError::Incomplete(
            FipsConfigurationField::Build,
        ))?;
        let environment = self.environment.ok_or(FipsConfigurationError::Incomplete(
            FipsConfigurationField::Environment,
        ))?;
        let ssp_flow = self.ssp_flow.ok_or(FipsConfigurationError::Incomplete(
            FipsConfigurationField::Ssp,
        ))?;
        for operation in ProviderOperation::ALL {
            let in_provider = self.provider.capabilities().contains(operation);
            let in_approved = approved.contains(operation);
            let in_non_approved = non_approved.contains(operation);
            if in_approved && in_non_approved {
                return Err(FipsConfigurationError::ServiceOverlap(operation));
            }
            if in_provider && !in_approved && !in_non_approved {
                return Err(FipsConfigurationError::ServiceUnclassified(operation));
            }
            if !in_provider && (in_approved || in_non_approved) {
                return Err(FipsConfigurationError::ServiceUnsupported(operation));
            }
        }
        if !approved.is_empty() {
            return Err(FipsConfigurationError::ApprovedServicesRequireExactIdentity);
        }
        let ssp = FipsSspPolicy::from_provider(ssp_flow, self.provider.destruction_targets());
        Ok(FipsModuleConfig {
            provider: self.provider,
            approved,
            non_approved,
            build,
            environment,
            ssp,
            self_tests: self.self_tests,
        })
    }
}
