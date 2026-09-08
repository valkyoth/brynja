use crate::{Error, Fallback, Profile, Request, Route};

/// Non-authorizing, affine selection model. It never executes an algorithm.
///
/// Current public construction cannot activate any candidate:
/// ```
/// use brynja_acceleration_contract_fixture::{Backend, ContractSession, Error, Profile, Request, Route};
/// let portable = ContractSession::begin(Request::Portable)?;
/// assert_eq!(portable.finish(), Ok(Route::Portable(None)));
/// assert!(matches!(ContractSession::begin(Request::Require(Backend::ArmSha512, Profile::Ordinary)), Err(Error::NotOperational)));
/// # Ok::<(), Error>(())
/// ```
/// A fabricated route is not a session:
/// ```compile_fail
/// use brynja_acceleration_contract_fixture::{ContractSession, Route};
/// let forged = ContractSession { route: Route::Portable(None), failure: None };
/// ```
/// A finished session cannot be reused:
/// ```compile_fail
/// use brynja_acceleration_contract_fixture::{ContractSession, Request};
/// let state = ContractSession::begin(Request::Portable).unwrap();
/// let _ = state.finish();
/// let _ = state.finish();
/// ```
pub struct ContractSession {
    route: Route,
    failure: Option<Error>,
}

// This private model input cannot be supplied by downstream code. Real
// execution will require sealed authority, not these model predicates.
pub(crate) struct Eligibility {
    pub(crate) project_ready: bool,
    pub(crate) public_reachable: bool,
    pub(crate) platform_supported: bool,
    pub(crate) hardened_ready: bool,
    pub(crate) healthy: bool,
}

impl ContractSession {
    /// Constructs a model using the current, blocked operational disposition.
    /// No review, FIPS, CPU-flag boolean or caller-supplied readiness is accepted.
    pub fn begin(request: Request) -> Result<Self, Error> {
        Self::select(
            request,
            Eligibility {
                project_ready: false,
                public_reachable: false,
                platform_supported: false,
                hardened_ready: false,
                healthy: true,
            },
        )
    }

    pub(crate) fn select(request: Request, evidence: Eligibility) -> Result<Self, Error> {
        let (backend, profile) = match request {
            Request::Portable => {
                return Ok(Self {
                    route: Route::Portable(None),
                    failure: None,
                });
            }
            Request::Prefer(backend, profile) | Request::Require(backend, profile) => {
                (backend, profile)
            }
        };
        // Integrity faults are never transformed into a preference fallback.
        let error = if !evidence.healthy {
            Some(Error::Quarantined)
        } else if !evidence.project_ready || !evidence.public_reachable {
            Some(Error::NotOperational)
        } else if !evidence.platform_supported {
            Some(Error::UnsupportedPlatform)
        } else if matches!(profile, Profile::Hardened) && !evidence.hardened_ready {
            Some(Error::UnsupportedProfile)
        } else {
            None
        };
        match error {
            None => Ok(Self {
                route: Route::Accelerated(backend, profile),
                failure: None,
            }),
            Some(Error::Quarantined) => Err(Error::Quarantined),
            Some(reason) if matches!(request, Request::Prefer(_, _)) => Ok(Self {
                route: Route::Portable(Some(Fallback {
                    backend,
                    profile,
                    reason,
                })),
                failure: None,
            }),
            Some(reason) => Err(reason),
        }
    }

    /// Returns diagnostics, not an execution token. Failed sessions expose no route.
    pub const fn route(&self) -> Result<Route, Error> {
        match self.failure {
            Some(reason) => Err(reason),
            None => Ok(self.route),
        }
    }

    /// Models terminal loss of an established lease or integrity failure.
    /// There is no public method to restore health or migrate state implicitly.
    /// The first failure is retained, even if later notifications differ.
    pub fn fail_closed(&mut self, integrity_failure: bool) {
        if self.failure.is_none() {
            self.failure = Some(if integrity_failure {
                Error::Quarantined
            } else {
                Error::AuthorityLost
            });
        }
    }

    /// Consumes this model; no crypto output or reusable permit is produced.
    pub const fn finish(self) -> Result<Route, Error> {
        self.route()
    }
}
