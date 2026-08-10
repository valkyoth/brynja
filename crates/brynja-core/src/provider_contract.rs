//! Transactional provider installation and opaque exact-operation handles.

use crate::{
    DestructionTargets, ProviderCapabilities, ProviderFrame, ProviderOperation, ProviderRequest,
    ProviderRequestError, ResourceBudget, WorkBudget,
};

/// One mandatory provider-installation field.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ProviderInstallationField {
    /// Frozen exact-operation capabilities.
    Capabilities,
    /// Frozen caller-selected resource limits.
    Resources,
    /// Frozen caller-selected work limit.
    Work,
    /// Mandatory secret-destruction duties.
    DestructionTargets,
}

/// A closed provider-installation failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ProviderInstallationError {
    /// A mandatory field was assigned twice.
    Duplicate(ProviderInstallationField),
    /// A mandatory field was not assigned.
    Incomplete(ProviderInstallationField),
    /// The declared destruction-duty set was empty.
    EmptyDestructionTargets,
}

/// A named, transactional provider-installation builder.
///
/// The builder has no effects and mutates no registry. Only [`Self::install`]
/// yields an [`InstalledProvider`], after every field is present and valid.
#[must_use = "provider installation must be completed or explicitly discarded"]
pub struct ProviderInstallation {
    capabilities: Option<ProviderCapabilities>,
    resources: Option<ResourceBudget>,
    work: Option<WorkBudget>,
    destruction_targets: Option<DestructionTargets>,
}

impl ProviderInstallation {
    /// Starts an empty provider installation.
    pub const fn begin() -> Self {
        Self {
            capabilities: None,
            resources: None,
            work: None,
            destruction_targets: None,
        }
    }

    /// Assigns the frozen exact-operation capability snapshot.
    pub const fn capabilities(
        mut self,
        capabilities: ProviderCapabilities,
    ) -> Result<Self, ProviderInstallationError> {
        if self.capabilities.is_some() {
            Err(ProviderInstallationError::Duplicate(
                ProviderInstallationField::Capabilities,
            ))
        } else {
            self.capabilities = Some(capabilities);
            Ok(self)
        }
    }

    /// Assigns frozen caller-selected resource limits.
    pub const fn resources(
        mut self,
        resources: ResourceBudget,
    ) -> Result<Self, ProviderInstallationError> {
        if self.resources.is_some() {
            Err(ProviderInstallationError::Duplicate(
                ProviderInstallationField::Resources,
            ))
        } else {
            self.resources = Some(resources);
            Ok(self)
        }
    }

    /// Assigns the frozen caller-selected work limit.
    pub const fn work(mut self, work: WorkBudget) -> Result<Self, ProviderInstallationError> {
        if self.work.is_some() {
            Err(ProviderInstallationError::Duplicate(
                ProviderInstallationField::Work,
            ))
        } else {
            self.work = Some(work);
            Ok(self)
        }
    }

    /// Assigns every location where this provider may own a secret copy.
    pub const fn destruction_targets(
        mut self,
        targets: DestructionTargets,
    ) -> Result<Self, ProviderInstallationError> {
        if self.destruction_targets.is_some() {
            Err(ProviderInstallationError::Duplicate(
                ProviderInstallationField::DestructionTargets,
            ))
        } else {
            self.destruction_targets = Some(targets);
            Ok(self)
        }
    }

    /// Atomically freezes the complete provider contract.
    pub const fn install(self) -> Result<InstalledProvider, ProviderInstallationError> {
        let capabilities = match self.capabilities {
            Some(value) => value,
            None => {
                return Err(ProviderInstallationError::Incomplete(
                    ProviderInstallationField::Capabilities,
                ));
            }
        };
        let resources = match self.resources {
            Some(value) => value,
            None => {
                return Err(ProviderInstallationError::Incomplete(
                    ProviderInstallationField::Resources,
                ));
            }
        };
        let work = match self.work {
            Some(value) => value,
            None => {
                return Err(ProviderInstallationError::Incomplete(
                    ProviderInstallationField::Work,
                ));
            }
        };
        let destruction_targets = match self.destruction_targets {
            Some(value) => value,
            None => {
                return Err(ProviderInstallationError::Incomplete(
                    ProviderInstallationField::DestructionTargets,
                ));
            }
        };
        if destruction_targets.is_empty() {
            return Err(ProviderInstallationError::EmptyDestructionTargets);
        }
        Ok(InstalledProvider {
            capabilities,
            resources,
            work,
            destruction_targets,
        })
    }
}

/// One frozen installed provider contract.
///
/// It contains no implementation pointer, native handle, algorithm policy, or
/// fallback chain. Platform and cryptographic packages implement effects
/// downstream while protocol code retains this upstream contract.
pub struct InstalledProvider {
    capabilities: ProviderCapabilities,
    resources: ResourceBudget,
    work: WorkBudget,
    destruction_targets: DestructionTargets,
}

impl InstalledProvider {
    /// Returns an opaque borrowed handle to this exact installed contract.
    #[must_use]
    pub const fn handle(&self) -> ProviderHandle<'_> {
        ProviderHandle { provider: self }
    }

    /// Returns the immutable capability snapshot for policy inspection.
    #[must_use]
    pub const fn capabilities(&self) -> ProviderCapabilities {
        self.capabilities
    }

    /// Returns the immutable mandatory destruction-duty set.
    #[must_use]
    pub const fn destruction_targets(&self) -> DestructionTargets {
        self.destruction_targets
    }

    pub(crate) const fn resources(&self) -> ResourceBudget {
        self.resources
    }

    pub(crate) const fn work(&self) -> WorkBudget {
        self.work
    }
}

/// A capability-authorization failure on one explicitly chosen provider.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ProviderAuthorizationError {
    /// The chosen provider did not declare this exact operation.
    Unsupported(ProviderOperation),
}

/// An opaque borrowed handle to one explicitly selected provider contract.
///
/// The handle cannot be constructed, cloned, copied, formatted, serialized,
/// or converted to a provider-native identifier by callers.
///
/// ```compile_fail
/// use brynja_core::ProviderHandle;
///
/// fn duplicate(handle: ProviderHandle<'_>) {
///     let _first = handle.clone();
/// }
/// ```
///
/// ```compile_fail
/// use brynja_core::ProviderHandle;
///
/// fn reveal(handle: ProviderHandle<'_>) {
///     let _ = format!("{handle:?}");
/// }
/// ```
pub struct ProviderHandle<'provider> {
    provider: &'provider InstalledProvider,
}

impl<'provider> ProviderHandle<'provider> {
    /// Authorizes exactly one declared operation on this chosen provider.
    ///
    /// Failure never searches another provider and never falls back.
    pub const fn authorize(
        self,
        operation: ProviderOperation,
    ) -> Result<ProviderAuthorization<'provider>, ProviderAuthorizationError> {
        if self.provider.capabilities.contains(operation) {
            Ok(ProviderAuthorization {
                provider: self.provider,
                operation,
            })
        } else {
            Err(ProviderAuthorizationError::Unsupported(operation))
        }
    }

    pub(crate) fn references(&self, provider: &InstalledProvider) -> bool {
        core::ptr::eq(self.provider, provider)
    }
}

/// A non-forgeable token bound to one provider and one exact operation.
///
/// ```compile_fail
/// use brynja_core::ProviderAuthorization;
///
/// fn duplicate(token: ProviderAuthorization<'_>) {
///     let _first = token.clone();
/// }
/// ```
#[must_use = "authorization must prepare its exact bounded provider request"]
pub struct ProviderAuthorization<'provider> {
    provider: &'provider InstalledProvider,
    operation: ProviderOperation,
}

impl<'provider> ProviderAuthorization<'provider> {
    /// Returns the only exact operation authorized by this token.
    #[must_use]
    pub const fn operation(&self) -> ProviderOperation {
        self.operation
    }

    /// Checks caller limits and prepares version-neutral request metadata.
    pub const fn prepare<'data>(
        self,
        frame: ProviderFrame<'data>,
    ) -> Result<ProviderRequest<'provider, 'data>, ProviderRequestError> {
        ProviderRequest::prepare(self.operation, frame, self.provider)
    }
}
