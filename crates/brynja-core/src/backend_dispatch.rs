//! Exact-operation backend policy selection and dispatch authority.

use core::marker::PhantomData;

use crate::{
    BackendClass, BackendHealthSnapshot, BackendHealthState, BackendIdentity, BackendPolicy,
    BackendRuntimeGeneration, BackendServiceApproval, BackendSession, ProviderOperation,
};

/// Non-forgeable, thread-bound authority for one healthy exact backend.
///
/// ```compile_fail
/// use brynja_core::ActiveBackend;
///
/// fn duplicate(active: ActiveBackend<'_>) {
///     let _copy = active.clone();
/// }
/// ```
///
/// ```compile_fail
/// use brynja_core::ActiveBackend;
///
/// fn move_to_thread(active: ActiveBackend<'static>) {
///     std::thread::spawn(move || drop(active));
/// }
/// ```
///
/// ```compile_fail
/// use brynja_core::ActiveBackend;
///
/// fn reveal(active: ActiveBackend<'_>) {
///     let _ = format!("{active:?}");
/// }
/// ```
#[must_use = "active backend authority must govern exact-operation dispatch"]
pub struct ActiveBackend<'session> {
    pub(crate) session: &'session BackendSession,
    pub(crate) health_generation: u64,
    pub(crate) runtime: BackendRuntimeGeneration,
    pub(crate) thread_bound: PhantomData<*mut ()>,
}

impl ActiveBackend<'_> {
    /// Returns a non-authorizing health snapshot.
    #[must_use]
    pub fn snapshot(&self) -> BackendHealthSnapshot {
        self.session.snapshot()
    }
}

/// A closed, value-free backend-dispatch refusal.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum BackendDispatchError {
    /// No candidate exists for a policy that requires one.
    Unavailable,
    /// The candidate has never passed its startup KAT.
    Unhealthy,
    /// The candidate is permanently quarantined.
    Quarantined,
    /// Authority belongs to an earlier health generation.
    StaleGeneration,
    /// Authority belongs to another runtime or process generation.
    RuntimeChanged,
    /// The exact provider operation is unsupported.
    UnsupportedOperation,
    /// The supplied backend class is not allowed by the policy.
    BackendClassMismatch,
    /// A validated-module policy lacks exact approved-module evidence.
    ApprovalUnavailable,
    /// The mandatory scalar backend was unavailable or invalid.
    ScalarUnavailable,
    /// The CPU execution lease belongs to another session or runtime.
    CpuLeaseMismatch,
    /// The current CPU or hart differs from the leased observation.
    CpuChanged,
    /// The complete usable feature predicate no longer holds.
    CpuFeaturesUnavailable,
    /// Required operating-system or architectural state is unavailable.
    CpuOperatingStateUnavailable,
    /// The platform migration or hot-plug generation changed.
    CpuMigrationGenerationChanged,
}

/// Explicit reason for one backend selection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum BackendSelectionReason {
    /// Scalar execution was explicitly required.
    ScalarRequired,
    /// An admitted accelerated backend was selected.
    Accelerated,
    /// Opportunistic selection explicitly fell back to scalar.
    ScalarFallback(BackendFallbackReason),
    /// An exact approved validated module was selected.
    ValidatedModule,
}

/// Closed reason for an explicit opportunistic scalar fallback.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum BackendFallbackReason {
    /// No accelerated candidate was supplied.
    CandidateUnavailable,
    /// The candidate had not completed a KAT.
    CandidateUnhealthy,
    /// The candidate was permanently quarantined.
    CandidateQuarantined,
    /// Candidate authority was stale.
    CandidateStale,
    /// The candidate did not support this exact operation.
    OperationUnsupported,
}

/// A secret-free, non-authorizing selection report.
///
/// Reports are observational. They cannot be converted back into dispatch
/// authority and do not claim that an operation executed or completed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BackendSelectionReport {
    identity: BackendIdentity,
    operation: ProviderOperation,
    policy: BackendPolicy,
    reason: BackendSelectionReason,
    service_approval: BackendServiceApproval,
}

impl BackendSelectionReport {
    /// Returns the selected sealed backend identity.
    #[must_use]
    pub const fn identity(self) -> BackendIdentity {
        self.identity
    }

    /// Returns the exact selected operation.
    #[must_use]
    pub const fn operation(self) -> ProviderOperation {
        self.operation
    }

    /// Returns the enforced policy.
    #[must_use]
    pub const fn policy(self) -> BackendPolicy {
        self.policy
    }

    /// Returns the explicit selection or fallback reason.
    #[must_use]
    pub const fn reason(self) -> BackendSelectionReason {
        self.reason
    }

    /// Returns observational approval status.
    #[must_use]
    pub const fn service_approval(self) -> BackendServiceApproval {
        self.service_approval
    }
}

/// Thread-bound authority for one exact backend and provider operation.
///
/// This token contains no function pointer and executes no instruction. A
/// later direct backend entry point must consume or borrow it and validate the
/// generation immediately before calling its isolated kernel.
///
/// ```compile_fail
/// use brynja_core::BackendDispatch;
///
/// fn duplicate(dispatch: BackendDispatch<'_>) {
///     let _copy = dispatch.clone();
/// }
/// ```
#[must_use = "dispatch authority must govern one exact direct backend entry"]
pub struct BackendDispatch<'session> {
    pub(crate) session: &'session BackendSession,
    identity: BackendIdentity,
    operation: ProviderOperation,
    policy: BackendPolicy,
    reason: BackendSelectionReason,
    health_generation: u64,
    runtime: BackendRuntimeGeneration,
    thread_bound: PhantomData<*mut ()>,
}

impl BackendDispatch<'_> {
    /// Revalidates logical health and runtime authority.
    ///
    /// For accelerated backends this is deliberately insufficient to enter a
    /// kernel. The separate direct entry boundary additionally acquires a
    /// sealed migration-excluding guard and revalidates logical authority after
    /// every platform callback.
    pub fn validate(&self, runtime: BackendRuntimeGeneration) -> Result<(), BackendDispatchError> {
        validate_authority(
            self.session,
            self.identity,
            self.operation,
            self.health_generation,
            self.runtime,
            runtime,
        )
    }

    /// Returns the exact operation authorized by this token.
    #[must_use]
    pub const fn operation(&self) -> ProviderOperation {
        self.operation
    }

    /// Returns a non-authorizing selection report.
    #[must_use]
    pub fn report(&self) -> BackendSelectionReport {
        BackendSelectionReport {
            identity: self.identity,
            operation: self.operation,
            policy: self.policy,
            reason: self.reason,
            service_approval: self.session.snapshot().service_approval(),
        }
    }
}

impl ActiveBackend<'_> {
    /// Authorizes one exact operation without policy fallback.
    pub fn authorize_backend(
        &self,
        operation: ProviderOperation,
        runtime: BackendRuntimeGeneration,
    ) -> Result<BackendDispatch<'_>, BackendDispatchError> {
        let (policy, reason) = match self.snapshot().identity().class() {
            BackendClass::Scalar => (
                BackendPolicy::ScalarOnly,
                BackendSelectionReason::ScalarRequired,
            ),
            BackendClass::Accelerated => (
                BackendPolicy::RequiredAccelerated,
                BackendSelectionReason::Accelerated,
            ),
            BackendClass::ValidatedModule => (
                BackendPolicy::ValidatedModuleOnly,
                BackendSelectionReason::ValidatedModule,
            ),
        };
        authorize_with_policy(self, operation, runtime, policy, reason)
    }
}

/// Selects one exact backend under the caller's explicit policy.
///
/// Opportunistic mode alone may fall back, and the returned report always
/// records why. Required acceleration and validated-module policies fail
/// closed. Scalar fallback calls the scalar authority directly and cannot
/// recurse into this selector.
pub fn select_backend<'session>(
    policy: BackendPolicy,
    operation: ProviderOperation,
    runtime: BackendRuntimeGeneration,
    preferred: Option<&ActiveBackend<'session>>,
    scalar: &ActiveBackend<'session>,
) -> Result<BackendDispatch<'session>, BackendDispatchError> {
    match policy {
        BackendPolicy::ScalarOnly => authorize_scalar(
            scalar,
            operation,
            runtime,
            policy,
            BackendSelectionReason::ScalarRequired,
        ),
        BackendPolicy::Opportunistic => {
            let reason = match preferred {
                Some(active) => {
                    if !matches!(
                        active.snapshot().identity().class(),
                        BackendClass::Accelerated
                    ) {
                        return Err(BackendDispatchError::BackendClassMismatch);
                    }
                    match authorize_with_policy(
                        active,
                        operation,
                        runtime,
                        policy,
                        BackendSelectionReason::Accelerated,
                    ) {
                        Ok(dispatch) => return Ok(dispatch),
                        Err(error) => fallback_reason(error)?,
                    }
                }
                None => BackendFallbackReason::CandidateUnavailable,
            };
            authorize_scalar(
                scalar,
                operation,
                runtime,
                policy,
                BackendSelectionReason::ScalarFallback(reason),
            )
        }
        BackendPolicy::RequiredAccelerated => {
            let Some(active) = preferred else {
                return Err(BackendDispatchError::Unavailable);
            };
            if !matches!(
                active.snapshot().identity().class(),
                BackendClass::Accelerated
            ) {
                return Err(BackendDispatchError::BackendClassMismatch);
            }
            authorize_with_policy(
                active,
                operation,
                runtime,
                policy,
                BackendSelectionReason::Accelerated,
            )
        }
        BackendPolicy::ValidatedModuleOnly => {
            let Some(active) = preferred else {
                return Err(BackendDispatchError::Unavailable);
            };
            let snapshot = active.snapshot();
            if !matches!(snapshot.identity().class(), BackendClass::ValidatedModule) {
                return Err(BackendDispatchError::BackendClassMismatch);
            }
            if !matches!(
                snapshot.service_approval(),
                BackendServiceApproval::Approved
            ) {
                return Err(BackendDispatchError::ApprovalUnavailable);
            }
            authorize_with_policy(
                active,
                operation,
                runtime,
                policy,
                BackendSelectionReason::ValidatedModule,
            )
        }
    }
}

fn authorize_scalar<'session>(
    scalar: &ActiveBackend<'session>,
    operation: ProviderOperation,
    runtime: BackendRuntimeGeneration,
    policy: BackendPolicy,
    reason: BackendSelectionReason,
) -> Result<BackendDispatch<'session>, BackendDispatchError> {
    if !matches!(scalar.snapshot().identity().class(), BackendClass::Scalar) {
        return Err(BackendDispatchError::ScalarUnavailable);
    }
    authorize_with_policy(scalar, operation, runtime, policy, reason)
        .map_err(|_| BackendDispatchError::ScalarUnavailable)
}

fn authorize_with_policy<'session>(
    active: &ActiveBackend<'session>,
    operation: ProviderOperation,
    runtime: BackendRuntimeGeneration,
    policy: BackendPolicy,
    reason: BackendSelectionReason,
) -> Result<BackendDispatch<'session>, BackendDispatchError> {
    let identity = active.snapshot().identity();
    validate_authority(
        active.session,
        identity,
        operation,
        active.health_generation,
        active.runtime,
        runtime,
    )?;
    Ok(BackendDispatch {
        session: active.session,
        identity,
        operation,
        policy,
        reason,
        health_generation: active.health_generation,
        runtime: active.runtime,
        thread_bound: PhantomData,
    })
}

fn validate_authority(
    session: &BackendSession,
    identity: BackendIdentity,
    operation: ProviderOperation,
    health_generation: u64,
    authority_runtime: BackendRuntimeGeneration,
    current_runtime: BackendRuntimeGeneration,
) -> Result<(), BackendDispatchError> {
    let snapshot = session.snapshot();
    if snapshot.identity() != identity {
        return Err(BackendDispatchError::BackendClassMismatch);
    }
    if authority_runtime != current_runtime || snapshot.runtime_generation() != current_runtime {
        return Err(BackendDispatchError::RuntimeChanged);
    }
    match snapshot.state() {
        BackendHealthState::NeverTested | BackendHealthState::Testing => {
            return Err(BackendDispatchError::Unhealthy);
        }
        BackendHealthState::Quarantined => return Err(BackendDispatchError::Quarantined),
        BackendHealthState::Healthy => {}
    }
    if snapshot.generation() != health_generation {
        return Err(BackendDispatchError::StaleGeneration);
    }
    if !session.profile().operations().contains(operation) {
        return Err(BackendDispatchError::UnsupportedOperation);
    }
    Ok(())
}

fn fallback_reason(
    error: BackendDispatchError,
) -> Result<BackendFallbackReason, BackendDispatchError> {
    match error {
        BackendDispatchError::Unavailable => Ok(BackendFallbackReason::CandidateUnavailable),
        BackendDispatchError::Unhealthy => Ok(BackendFallbackReason::CandidateUnhealthy),
        BackendDispatchError::Quarantined => Ok(BackendFallbackReason::CandidateQuarantined),
        BackendDispatchError::StaleGeneration | BackendDispatchError::RuntimeChanged => {
            Ok(BackendFallbackReason::CandidateStale)
        }
        BackendDispatchError::UnsupportedOperation => {
            Ok(BackendFallbackReason::OperationUnsupported)
        }
        BackendDispatchError::BackendClassMismatch
        | BackendDispatchError::ApprovalUnavailable
        | BackendDispatchError::ScalarUnavailable
        | BackendDispatchError::CpuLeaseMismatch
        | BackendDispatchError::CpuChanged
        | BackendDispatchError::CpuFeaturesUnavailable
        | BackendDispatchError::CpuOperatingStateUnavailable
        | BackendDispatchError::CpuMigrationGenerationChanged => Err(error),
    }
}
