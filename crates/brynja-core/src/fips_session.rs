//! Permanent-failure self-test and service-authorization state for one module.
//!
//! Authorization cannot be copied or formatted into an accidental durable
//! service indicator:
//!
//! ```compile_fail
//! use brynja_core::FipsServiceAuthorization;
//! fn require_clone<T: Clone>() {}
//! require_clone::<FipsServiceAuthorization<'static, 'static, 'static>>();
//! ```
//!
//! Authorization also cannot cross threads:
//!
//! ```compile_fail
//! use brynja_core::FipsServiceAuthorization;
//! fn require_send<T: Send>() {}
//! require_send::<FipsServiceAuthorization<'static, 'static, 'static>>();
//! ```
//!
//! Ordinary backend policy cannot be supplied as FIPS service classification:
//!
//! ```compile_fail
//! use brynja_core::{BackendPolicy, FipsModuleBuilder};
//! fn bypass(builder: FipsModuleBuilder<'_>) {
//!     let _ = builder.approved_services(BackendPolicy::Opportunistic);
//! }
//! ```

use core::{cell::Cell, marker::PhantomData};

use crate::{FipsModuleConfig, FipsSelfTestPlan, FipsServiceDisposition, ProviderOperation};

/// Runtime state of one exact future module configuration.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum FipsModuleState {
    /// Mandatory self-tests have not run.
    Uninitialized,
    /// One guarded self-test sequence is active.
    SelfTesting,
    /// Exact configured self-tests passed for this generation.
    Operational,
    /// A permanent failure forbids every service.
    Failed,
}

/// Closed permanent-failure classification.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum FipsModuleFault {
    /// A configured self-test failed.
    SelfTestFailed,
    /// Self-test execution unwound, was canceled, or was abandoned.
    SelfTestInterrupted,
    /// Self-test execution was entered recursively.
    ReentrantSelfTest,
    /// Runtime service state reached an impossible transition.
    ImpossibleState,
    /// A downstream module integrity event requires shutdown.
    CatastrophicFailure,
    /// The monotonic state generation was exhausted.
    GenerationExhausted,
}

/// Secret-free module-state snapshot.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FipsModuleSnapshot {
    state: FipsModuleState,
    generation: u64,
    fault: Option<FipsModuleFault>,
}

impl FipsModuleSnapshot {
    /// Returns the authoritative current state.
    #[must_use]
    pub const fn state(self) -> FipsModuleState {
        self.state
    }

    /// Returns the monotonic state generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the first permanent fault, if any.
    #[must_use]
    pub const fn fault(self) -> Option<FipsModuleFault> {
        self.fault
    }
}

#[derive(Clone, Copy)]
struct FipsStateRecord {
    state: FipsModuleState,
    generation: u64,
    fault: Option<FipsModuleFault>,
}

/// One result returned by the explicitly trusted self-test runner boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum FipsSelfTestResult {
    /// The runner completed every test it was asked to execute.
    Passed,
    /// The runner observed any test failure.
    Failed,
}

/// Security-critical hook that executes one exact frozen self-test plan.
///
/// Implementing this trait asserts a trusted boundary: returning `Passed`
/// means every requested integrity, known-answer, and conditional test really
/// completed successfully. Application code must not implement this trait as
/// a policy override. The trait neither executes nor validates cryptography by
/// itself, and its existence is not a FIPS validation claim.
pub trait FipsSelfTestRunner {
    /// Executes every category in `plan` and returns a mandatory result.
    fn run(&mut self, plan: FipsSelfTestPlan) -> FipsSelfTestResult;
}

/// A closed module-state transition failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum FipsModuleError {
    /// Self-tests are already active; the module is now failed.
    Reentrant,
    /// The module already completed self-tests.
    AlreadyOperational,
    /// Permanent failure forbids this transition.
    Failed,
    /// A configured self-test failed and permanently failed the module.
    SelfTestFailed,
    /// The internal state generation was exhausted.
    GenerationExhausted,
    /// The guard no longer owned the expected state.
    StateChanged,
}

/// A closed service-authorization failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum FipsServiceError {
    /// Mandatory self-tests have not completed.
    NotOperational,
    /// The module is permanently failed.
    ModuleFailed,
    /// The exact operation is not part of this provider contract.
    Unsupported(ProviderOperation),
}

/// Caller-owned state for one exact inert module configuration.
///
/// It is allocation-free, non-global, and does not execute cryptography.
pub struct FipsModuleSession<'config, 'provider> {
    config: &'config FipsModuleConfig<'provider>,
    state: Cell<FipsStateRecord>,
}

impl<'config, 'provider> FipsModuleSession<'config, 'provider> {
    /// Creates an uninitialized session without running a self-test.
    #[must_use]
    pub const fn new(config: &'config FipsModuleConfig<'provider>) -> Self {
        Self {
            config,
            state: Cell::new(FipsStateRecord {
                state: FipsModuleState::Uninitialized,
                generation: 1,
                fault: None,
            }),
        }
    }

    /// Returns secret-free non-authorizing state.
    #[must_use]
    pub fn snapshot(&self) -> FipsModuleSnapshot {
        let record = self.state.get();
        FipsModuleSnapshot {
            state: record.state,
            generation: record.generation,
            fault: record.fault,
        }
    }

    /// Runs the exact frozen plan through an explicitly trusted runner.
    ///
    /// Reentry, panic, unwind, cancellation, or an explicit failure latches a
    /// permanent module failure before this call returns control.
    pub fn run_self_tests<R: FipsSelfTestRunner + ?Sized>(
        &self,
        runner: &mut R,
    ) -> Result<(), FipsModuleError> {
        let guard = self.begin_self_tests()?;
        let result = runner.run(guard.plan());
        guard.complete(result)
    }

    fn begin_self_tests(
        &self,
    ) -> Result<FipsSelfTestGuard<'_, 'config, 'provider>, FipsModuleError> {
        let record = self.state.get();
        match record.state {
            FipsModuleState::Uninitialized => {
                let generation = self.next_generation(record)?;
                self.state.set(FipsStateRecord {
                    state: FipsModuleState::SelfTesting,
                    generation,
                    fault: None,
                });
                Ok(FipsSelfTestGuard {
                    session: self,
                    generation,
                    armed: true,
                })
            }
            FipsModuleState::SelfTesting => {
                self.fail_permanently(FipsModuleFault::ReentrantSelfTest);
                Err(FipsModuleError::Reentrant)
            }
            FipsModuleState::Operational => Err(FipsModuleError::AlreadyOperational),
            FipsModuleState::Failed => Err(FipsModuleError::Failed),
        }
    }

    /// Permanently fails the module after a downstream integrity event.
    pub fn catastrophic_failure(&self) {
        self.fail_permanently(FipsModuleFault::CatastrophicFailure);
    }

    /// Authorizes classification of one configured service only when operational.
    pub fn authorize(
        &self,
        operation: ProviderOperation,
    ) -> Result<FipsServiceAuthorization<'_, 'config, 'provider>, FipsServiceError> {
        let record = self.state.get();
        match record.state {
            FipsModuleState::Uninitialized | FipsModuleState::SelfTesting => {
                return Err(FipsServiceError::NotOperational);
            }
            FipsModuleState::Failed => return Err(FipsServiceError::ModuleFailed),
            FipsModuleState::Operational => {}
        }
        if !self.config.provider().capabilities().contains(operation) {
            return Err(FipsServiceError::Unsupported(operation));
        }
        let Some(disposition) = self.config.disposition(operation) else {
            self.fail_permanently(FipsModuleFault::ImpossibleState);
            return Err(FipsServiceError::ModuleFailed);
        };
        Ok(FipsServiceAuthorization {
            session: self,
            operation,
            disposition,
            generation: record.generation,
            thread_bound: PhantomData,
        })
    }

    fn next_generation(&self, record: FipsStateRecord) -> Result<u64, FipsModuleError> {
        match record.generation.checked_add(1) {
            Some(generation) => Ok(generation),
            None => {
                self.fail_permanently(FipsModuleFault::GenerationExhausted);
                Err(FipsModuleError::GenerationExhausted)
            }
        }
    }

    fn fail_permanently(&self, fault: FipsModuleFault) {
        let record = self.state.get();
        if matches!(record.state, FipsModuleState::Failed) {
            return;
        }
        let generation = record
            .generation
            .checked_add(1)
            .unwrap_or(record.generation);
        let fault = if generation == record.generation {
            FipsModuleFault::GenerationExhausted
        } else {
            fault
        };
        self.state.set(FipsStateRecord {
            state: FipsModuleState::Failed,
            generation,
            fault: Some(fault),
        });
    }
}

/// In-progress module self-test guard.
///
/// Drop after unwind, cancellation, or early return permanently fails the
/// session. This type cannot be cloned, copied, or formatted.
#[must_use = "self-tests must complete or permanently fail the module"]
struct FipsSelfTestGuard<'session, 'config, 'provider> {
    session: &'session FipsModuleSession<'config, 'provider>,
    generation: u64,
    armed: bool,
}

impl FipsSelfTestGuard<'_, '_, '_> {
    /// Returns the exact frozen plan for a trusted downstream test runner.
    #[must_use]
    pub const fn plan(&self) -> FipsSelfTestPlan {
        self.session.config.self_test_plan()
    }

    /// Consumes the trusted result and transitions to operational or failed.
    fn complete(mut self, result: FipsSelfTestResult) -> Result<(), FipsModuleError> {
        let record = self.session.state.get();
        if !matches!(record.state, FipsModuleState::SelfTesting)
            || record.generation != self.generation
        {
            self.session
                .fail_permanently(FipsModuleFault::ImpossibleState);
            self.armed = false;
            return Err(FipsModuleError::StateChanged);
        }
        if matches!(result, FipsSelfTestResult::Failed) {
            self.session
                .fail_permanently(FipsModuleFault::SelfTestFailed);
            self.armed = false;
            return Err(FipsModuleError::SelfTestFailed);
        }
        let generation = self.session.next_generation(record)?;
        self.session.state.set(FipsStateRecord {
            state: FipsModuleState::Operational,
            generation,
            fault: None,
        });
        self.armed = false;
        Ok(())
    }
}

impl Drop for FipsSelfTestGuard<'_, '_, '_> {
    fn drop(&mut self) {
        if self.armed {
            self.session
                .fail_permanently(FipsModuleFault::SelfTestInterrupted);
        }
    }
}

/// Non-forgeable authorization bound to one operational module session.
///
/// The token reports configuration classification only. It neither executes a
/// provider operation nor proves FIPS validation.
pub struct FipsServiceAuthorization<'session, 'config, 'provider> {
    session: &'session FipsModuleSession<'config, 'provider>,
    operation: ProviderOperation,
    disposition: FipsServiceDisposition,
    generation: u64,
    thread_bound: PhantomData<*mut ()>,
}

impl FipsServiceAuthorization<'_, '_, '_> {
    /// Returns the one exact operation bound to this token.
    #[must_use]
    pub const fn operation(&self) -> ProviderOperation {
        self.operation
    }

    /// Returns approved or non-approved configuration intent.
    #[must_use]
    pub const fn disposition(&self) -> FipsServiceDisposition {
        self.disposition
    }

    /// Reports whether the token still matches operational module state.
    #[must_use]
    pub fn is_current(&self) -> bool {
        let snapshot = self.session.snapshot();
        matches!(snapshot.state(), FipsModuleState::Operational)
            && snapshot.generation() == self.generation
    }
}
