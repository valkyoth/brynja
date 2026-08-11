//! Non-cryptographic, no_std state fixture for CPU admission harnesses.

#![no_std]

/// Selection policy exercised by the fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Policy {
    /// Portable reference only.
    ScalarOnly,
    /// Mock backend with explicit scalar fallback.
    Opportunistic,
    /// Mock backend with no fallback.
    Required,
}

/// Injected condition for one test execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    /// No fault.
    None,
    /// Complete required feature evidence is unavailable.
    Unsupported,
    /// Startup known-answer output differs from the reference.
    KnownAnswerMismatch,
    /// Operation output differs from the scalar reference.
    DifferentialMismatch,
}

/// Closed fixture refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// The backend has not completed initialization.
    Unhealthy,
    /// Required feature evidence was unavailable.
    Unsupported,
    /// A permanent integrity failure quarantined the backend.
    Quarantined,
    /// The mock output differed from the scalar reference.
    Mismatch,
}

/// Observable execution route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    /// Portable reference executed.
    Scalar,
    /// Forced mock backend executed after validation.
    Mock,
    /// Opportunistic policy explicitly fell back.
    ScalarFallback,
}

/// Successful fixture output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Output {
    /// Exact execution route.
    pub route: Route,
    /// Deterministic public test value.
    pub value: u8,
}

/// Caller-owned fixture session with no global or atomic state.
pub struct Session {
    supported: bool,
    healthy: bool,
    quarantined: bool,
    mock_calls: usize,
}

impl Session {
    /// Creates an uninitialized session from observational feature evidence.
    #[must_use]
    pub const fn new(supported: bool) -> Self {
        Self {
            supported,
            healthy: false,
            quarantined: false,
            mock_calls: 0,
        }
    }

    /// Runs the direct startup known-answer fixture.
    pub fn initialize(&mut self, fault: Fault) -> Result<(), Refusal> {
        if self.quarantined {
            return Err(Refusal::Quarantined);
        }
        if !self.supported || matches!(fault, Fault::Unsupported) {
            return Err(Refusal::Unsupported);
        }
        if matches!(fault, Fault::KnownAnswerMismatch) {
            self.quarantined = true;
            return Err(Refusal::Mismatch);
        }
        self.healthy = true;
        Ok(())
    }

    /// Executes one forced-policy fixture and differentially checks the result.
    pub fn execute(&mut self, policy: Policy, input: u8, fault: Fault) -> Result<Output, Refusal> {
        let scalar = reference(input);
        if matches!(policy, Policy::ScalarOnly) {
            return Ok(Output {
                route: Route::Scalar,
                value: scalar,
            });
        }
        if self.quarantined {
            return required_or_fallback(policy, scalar, Refusal::Quarantined);
        }
        if !self.supported || matches!(fault, Fault::Unsupported) {
            return required_or_fallback(policy, scalar, Refusal::Unsupported);
        }
        if !self.healthy {
            return required_or_fallback(policy, scalar, Refusal::Unhealthy);
        }
        self.mock_calls = self.mock_calls.saturating_add(1);
        let mock = if matches!(fault, Fault::DifferentialMismatch) {
            scalar ^ 1
        } else {
            scalar
        };
        if mock != scalar {
            self.quarantined = true;
            return Err(Refusal::Mismatch);
        }
        Ok(Output {
            route: Route::Mock,
            value: mock,
        })
    }

    /// Reports whether the first integrity fault permanently disabled the session.
    #[must_use]
    pub const fn quarantined(&self) -> bool {
        self.quarantined
    }

    /// Returns the exact number of direct mock entries.
    #[must_use]
    pub const fn mock_calls(&self) -> usize {
        self.mock_calls
    }
}

fn required_or_fallback(policy: Policy, scalar: u8, refusal: Refusal) -> Result<Output, Refusal> {
    if matches!(policy, Policy::Opportunistic) {
        Ok(Output {
            route: Route::ScalarFallback,
            value: scalar,
        })
    } else {
        Err(refusal)
    }
}

const fn reference(input: u8) -> u8 {
    input.rotate_left(3) ^ 0xa5
}

#[cfg(test)]
mod tests {
    use super::{Fault, Policy, Refusal, Route, Session};

    #[test]
    fn scalar_and_positive_forced_routes_are_exact() {
        let mut session = Session::new(true);
        assert_eq!(session.initialize(Fault::None), Ok(()));
        assert_eq!(
            session
                .execute(Policy::ScalarOnly, 7, Fault::None)
                .map(|value| value.route),
            Ok(Route::Scalar)
        );
        assert_eq!(
            session
                .execute(Policy::Required, 7, Fault::None)
                .map(|value| value.route),
            Ok(Route::Mock)
        );
        assert_eq!(session.mock_calls(), 1);
    }

    #[test]
    fn unsupported_required_mode_never_falls_back_or_enters_mock() {
        let mut session = Session::new(false);
        assert_eq!(session.initialize(Fault::None), Err(Refusal::Unsupported));
        assert_eq!(
            session.execute(Policy::Required, 1, Fault::None),
            Err(Refusal::Unsupported)
        );
        assert_eq!(session.mock_calls(), 0);
    }

    #[test]
    fn unsupported_opportunistic_mode_reports_scalar_fallback() {
        let mut session = Session::new(false);
        let output = session.execute(Policy::Opportunistic, 1, Fault::None);
        assert_eq!(output.map(|value| value.route), Ok(Route::ScalarFallback));
        assert_eq!(session.mock_calls(), 0);
    }

    #[test]
    fn known_answer_failure_quarantines_permanently() {
        let mut session = Session::new(true);
        assert_eq!(
            session.initialize(Fault::KnownAnswerMismatch),
            Err(Refusal::Mismatch)
        );
        assert!(session.quarantined());
        assert_eq!(session.initialize(Fault::None), Err(Refusal::Quarantined));
        assert_eq!(
            session.execute(Policy::Required, 2, Fault::None),
            Err(Refusal::Quarantined)
        );
    }

    #[test]
    fn differential_failure_quarantines_after_one_direct_entry() {
        let mut session = Session::new(true);
        assert_eq!(session.initialize(Fault::None), Ok(()));
        assert_eq!(
            session.execute(Policy::Required, 3, Fault::DifferentialMismatch),
            Err(Refusal::Mismatch)
        );
        assert!(session.quarantined());
        assert_eq!(session.mock_calls(), 1);
    }

    #[test]
    fn interleaved_sessions_share_no_health_or_call_state() {
        let mut first = Session::new(true);
        let mut second = Session::new(true);
        assert_eq!(
            first.initialize(Fault::KnownAnswerMismatch),
            Err(Refusal::Mismatch)
        );
        assert_eq!(second.initialize(Fault::None), Ok(()));
        assert_eq!(
            first.execute(Policy::Required, 4, Fault::None),
            Err(Refusal::Quarantined)
        );
        assert_eq!(
            second
                .execute(Policy::Required, 4, Fault::None)
                .map(|value| value.route),
            Ok(Route::Mock)
        );
        assert_eq!(first.mock_calls(), 0);
        assert_eq!(second.mock_calls(), 1);
    }
}
