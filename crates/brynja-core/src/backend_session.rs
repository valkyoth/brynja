//! Caller-owned backend health, KAT, generation, and quarantine state.

use core::{cell::Cell, marker::PhantomData};

use crate::{
    ActiveBackend, BackendCandidate, BackendClass, BackendIdentity, BackendProfile,
    BackendRuntimeGeneration,
};
/// Process-local health of one exact backend profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum BackendHealthState {
    /// No startup known-answer test has completed.
    NeverTested,
    /// A direct, non-dispatching known-answer test is in progress.
    Testing,
    /// The exact profile passed for the current runtime generation.
    Healthy,
    /// The profile is permanently disabled in this session.
    Quarantined,
}

/// Closed backend integrity-fault classification.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum BackendFault {
    /// A startup known-answer test failed.
    KnownAnswerFailed,
    /// Initialization unwound, was canceled, or otherwise did not complete.
    InitializationInterrupted,
    /// Initialization recursively attempted dispatch or another initialization.
    ReentrantInitialization,
    /// Evidence did not match the exact backend profile.
    EvidenceMismatch,
    /// Service approval was missing or attached to the wrong backend class.
    ApprovalMismatch,
    /// A monotonic health generation could not advance.
    GenerationExhausted,
    /// The state machine reached an impossible transition.
    ImpossibleState,
}

/// Observational service-approval status.
///
/// This report never authorizes execution and is not a FIPS validation claim.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum BackendServiceApproval {
    /// The ordinary scalar or accelerated backend has no module approval.
    NotApplicable,
    /// A validated-module policy has no current approval evidence.
    Unavailable,
    /// The trusted provider bound approval to this exact tested module.
    Approved,
}

/// A secret-free snapshot of one backend session.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BackendHealthSnapshot {
    identity: BackendIdentity,
    state: BackendHealthState,
    generation: u64,
    runtime: BackendRuntimeGeneration,
    fault: Option<BackendFault>,
    approval: BackendServiceApproval,
}

impl BackendHealthSnapshot {
    /// Returns the sealed backend identity.
    #[must_use]
    pub const fn identity(self) -> BackendIdentity {
        self.identity
    }

    /// Returns the process-local health state.
    #[must_use]
    pub const fn state(self) -> BackendHealthState {
        self.state
    }

    /// Returns the monotonic health generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the runtime generation bound to this health state.
    #[must_use]
    pub const fn runtime_generation(self) -> BackendRuntimeGeneration {
        self.runtime
    }

    /// Returns the first permanent integrity fault, if any.
    #[must_use]
    pub const fn fault(self) -> Option<BackendFault> {
        self.fault
    }

    /// Returns observational module-approval status.
    #[must_use]
    pub const fn service_approval(self) -> BackendServiceApproval {
        self.approval
    }
}

#[derive(Clone, Copy)]
struct HealthRecord {
    state: BackendHealthState,
    generation: u64,
    runtime: BackendRuntimeGeneration,
    fault: Option<BackendFault>,
    approval: BackendServiceApproval,
}

/// A backend-session construction failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum BackendSessionError {
    /// The public safe constructor received a non-scalar candidate.
    NonScalarCandidate,
}

/// One caller-owned, allocation-free, non-global backend health session.
///
/// It uses no atomics and is not a registry. Accelerated candidates are
/// admitted only by a later separately reviewed evidence boundary.
pub struct BackendSession {
    candidate: BackendCandidate,
    health: Cell<HealthRecord>,
}
impl BackendSession {
    /// Creates an inert scalar session from the safe scalar candidate.
    ///
    /// This does not run a KAT or return dispatch authority.
    pub const fn scalar(
        candidate: BackendCandidate,
        runtime: BackendRuntimeGeneration,
    ) -> Result<Self, BackendSessionError> {
        if matches!(candidate.profile().identity(), BackendIdentity::Scalar) {
            Ok(Self::new(candidate, runtime))
        } else {
            Err(BackendSessionError::NonScalarCandidate)
        }
    }

    /// Creates an inert session from an opaque evidence-backed candidate.
    ///
    /// This still grants no dispatch authority before a matching KAT result.
    #[must_use]
    pub const fn from_candidate(
        candidate: BackendCandidate,
        runtime: BackendRuntimeGeneration,
    ) -> Self {
        Self::new(candidate, runtime)
    }

    const fn new(candidate: BackendCandidate, runtime: BackendRuntimeGeneration) -> Self {
        let approval = match candidate.profile().identity().class() {
            BackendClass::ValidatedModule => BackendServiceApproval::Unavailable,
            BackendClass::Scalar | BackendClass::Accelerated => {
                BackendServiceApproval::NotApplicable
            }
        };
        Self {
            candidate,
            health: Cell::new(HealthRecord {
                state: BackendHealthState::NeverTested,
                generation: 1,
                runtime,
                fault: None,
                approval,
            }),
        }
    }

    /// Returns a non-authorizing, secret-free health snapshot.
    #[must_use]
    pub fn snapshot(&self) -> BackendHealthSnapshot {
        let record = self.health.get();
        BackendHealthSnapshot {
            identity: self.candidate.profile().identity(),
            state: record.state,
            generation: record.generation,
            runtime: record.runtime,
            fault: record.fault,
            approval: record.approval,
        }
    }

    /// Begins one direct, non-recursive startup KAT.
    ///
    /// Completion requires an opaque trusted-provider result. Dropping the
    /// returned guard permanently quarantines this session.
    pub fn begin_initialization(
        &self,
    ) -> Result<BackendInitialization<'_>, BackendInitializationError> {
        let record = self.health.get();
        match record.state {
            BackendHealthState::NeverTested => {
                let Some(generation) = record.generation.checked_add(1) else {
                    self.quarantine(BackendFault::GenerationExhausted);
                    return Err(BackendInitializationError::GenerationExhausted);
                };
                self.health.set(HealthRecord {
                    state: BackendHealthState::Testing,
                    generation,
                    fault: None,
                    ..record
                });
                Ok(BackendInitialization {
                    session: self,
                    testing_generation: generation,
                    armed: true,
                })
            }
            BackendHealthState::Testing => {
                self.quarantine(BackendFault::ReentrantInitialization);
                Err(BackendInitializationError::Reentrant)
            }
            BackendHealthState::Healthy => Err(BackendInitializationError::AlreadyHealthy),
            BackendHealthState::Quarantined => Err(BackendInitializationError::Quarantined),
        }
    }

    /// Invalidates inherited health after fork, clone, or runtime replacement.
    ///
    /// Permanent quarantine is never cleared by a runtime change.
    pub fn runtime_changed(&self, runtime: BackendRuntimeGeneration) {
        let record = self.health.get();
        if record.runtime == runtime {
            return;
        }
        if matches!(record.state, BackendHealthState::Quarantined) {
            return;
        }
        let Some(generation) = record.generation.checked_add(1) else {
            self.quarantine(BackendFault::GenerationExhausted);
            return;
        };
        self.health.set(HealthRecord {
            state: BackendHealthState::NeverTested,
            generation,
            runtime,
            fault: None,
            approval: match self.candidate.profile().identity().class() {
                BackendClass::ValidatedModule => BackendServiceApproval::Unavailable,
                BackendClass::Scalar | BackendClass::Accelerated => {
                    BackendServiceApproval::NotApplicable
                }
            },
        });
    }

    pub(crate) fn quarantine(&self, fault: BackendFault) {
        let record = self.health.get();
        if matches!(record.state, BackendHealthState::Quarantined) {
            return;
        }
        let generation = match record.generation.checked_add(1) {
            Some(value) => value,
            None => record.generation,
        };
        let retained_fault = if generation == record.generation {
            BackendFault::GenerationExhausted
        } else {
            fault
        };
        self.health.set(HealthRecord {
            state: BackendHealthState::Quarantined,
            generation,
            fault: Some(retained_fault),
            approval: BackendServiceApproval::Unavailable,
            ..record
        });
    }

    pub(crate) const fn profile(&self) -> BackendProfile {
        self.candidate.profile()
    }
}

/// A closed startup-initialization failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum BackendInitializationError {
    /// Another initialization is in progress; the backend was quarantined.
    Reentrant,
    /// This exact session is already healthy.
    AlreadyHealthy,
    /// This exact session is permanently quarantined.
    Quarantined,
    /// The monotonic health generation was exhausted.
    GenerationExhausted,
    /// KAT evidence did not match the exact profile or generation.
    EvidenceMismatch,
    /// Approval evidence did not match the backend class.
    ApprovalMismatch,
    /// The initializer no longer owned the expected testing state.
    StateChanged,
}

/// Opaque trusted-provider proof that one direct startup KAT passed.
///
/// It has no public constructor. Project tests and later reviewed backend
/// packages construct it only inside the trusted provider-effect boundary.
///
/// Safe downstream code cannot claim that a KAT passed:
///
/// ```compile_fail
/// use brynja_core::BackendKatPass;
///
/// fn forge() -> BackendKatPass {
///     BackendKatPass {}
/// }
/// ```
pub struct BackendKatPass {
    profile: BackendProfile,
    runtime: BackendRuntimeGeneration,
    testing_generation: u64,
    approval: BackendServiceApproval,
    thread_bound: PhantomData<*mut ()>,
}

impl BackendKatPass {
    #[cfg(test)]
    pub(crate) const fn for_test(
        profile: BackendProfile,
        runtime: BackendRuntimeGeneration,
        testing_generation: u64,
        approval: BackendServiceApproval,
    ) -> Self {
        Self {
            profile,
            runtime,
            testing_generation,
            approval,
            thread_bound: PhantomData,
        }
    }
}

/// Opaque trusted-provider proof that one direct startup KAT failed.
///
/// It has no public constructor and therefore cannot be forged from a public
/// fault category alone.
pub struct BackendKatFailure {
    profile: BackendProfile,
    runtime: BackendRuntimeGeneration,
    testing_generation: u64,
    fault: BackendFault,
    thread_bound: PhantomData<*mut ()>,
}

impl BackendKatFailure {
    #[cfg(test)]
    pub(crate) const fn for_test(
        profile: BackendProfile,
        runtime: BackendRuntimeGeneration,
        testing_generation: u64,
        fault: BackendFault,
    ) -> Self {
        Self {
            profile,
            runtime,
            testing_generation,
            fault,
            thread_bound: PhantomData,
        }
    }
}

/// In-progress direct KAT guard.
///
/// Dropping this guard after panic, cancellation, or early return permanently
/// quarantines the backend. It cannot be cloned, copied, or formatted.
pub struct BackendInitialization<'session> {
    session: &'session BackendSession,
    testing_generation: u64,
    armed: bool,
}

impl<'session> BackendInitialization<'session> {
    /// Completes initialization only with exact opaque KAT-pass evidence.
    pub fn complete(
        mut self,
        pass: BackendKatPass,
    ) -> Result<ActiveBackend<'session>, BackendInitializationError> {
        let record = self.session.health.get();
        if !matches!(record.state, BackendHealthState::Testing)
            || record.generation != self.testing_generation
        {
            self.session.quarantine(BackendFault::ImpossibleState);
            self.armed = false;
            return Err(BackendInitializationError::StateChanged);
        }
        if pass.profile != self.session.profile()
            || pass.runtime != record.runtime
            || pass.testing_generation != record.generation
        {
            self.session.quarantine(BackendFault::EvidenceMismatch);
            self.armed = false;
            return Err(BackendInitializationError::EvidenceMismatch);
        }
        let valid_approval = match self.session.profile().identity().class() {
            BackendClass::ValidatedModule => {
                matches!(pass.approval, BackendServiceApproval::Approved)
            }
            BackendClass::Scalar | BackendClass::Accelerated => {
                matches!(pass.approval, BackendServiceApproval::NotApplicable)
            }
        };
        if !valid_approval {
            self.session.quarantine(BackendFault::ApprovalMismatch);
            self.armed = false;
            return Err(BackendInitializationError::ApprovalMismatch);
        }
        let Some(generation) = record.generation.checked_add(1) else {
            self.session.quarantine(BackendFault::GenerationExhausted);
            self.armed = false;
            return Err(BackendInitializationError::GenerationExhausted);
        };
        self.session.health.set(HealthRecord {
            state: BackendHealthState::Healthy,
            generation,
            fault: None,
            approval: pass.approval,
            ..record
        });
        self.armed = false;
        Ok(ActiveBackend {
            session: self.session,
            health_generation: generation,
            runtime: record.runtime,
            thread_bound: PhantomData,
        })
    }

    /// Permanently quarantines only with exact opaque KAT-failure evidence.
    pub fn fail(mut self, failure: BackendKatFailure) -> Result<(), BackendInitializationError> {
        let record = self.session.health.get();
        if !matches!(record.state, BackendHealthState::Testing)
            || record.generation != self.testing_generation
        {
            self.session.quarantine(BackendFault::ImpossibleState);
            self.armed = false;
            return Err(BackendInitializationError::StateChanged);
        }
        if failure.profile != self.session.profile()
            || failure.runtime != record.runtime
            || failure.testing_generation != record.generation
        {
            self.session.quarantine(BackendFault::EvidenceMismatch);
            self.armed = false;
            return Err(BackendInitializationError::EvidenceMismatch);
        }
        self.session.quarantine(failure.fault);
        self.armed = false;
        Ok(())
    }
}

impl Drop for BackendInitialization<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.session
                .quarantine(BackendFault::InitializationInterrupted);
        }
    }
}
