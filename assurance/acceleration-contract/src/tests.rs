use crate::selection::Eligibility;
use crate::{Backend, ContractSession, Error, Fallback, Profile, Request, Route};

fn flags(bits: u8) -> Eligibility {
    Eligibility {
        project_ready: bits & 1 != 0,
        public_reachable: bits & 2 != 0,
        platform_supported: bits & 4 != 0,
        hardened_ready: bits & 8 != 0,
        healthy: bits & 16 != 0,
    }
}

#[test]
fn public_model_never_activates_current_kernels() {
    assert_eq!(
        ContractSession::begin(Request::Portable).map(ContractSession::finish),
        Ok(Ok(Route::Portable(None)))
    );
    for backend in Backend::ALL {
        for profile in [Profile::Ordinary, Profile::Hardened] {
            assert_eq!(
                ContractSession::begin(Request::Require(backend, profile))
                    .map(ContractSession::finish),
                Err(Error::NotOperational)
            );
            assert_eq!(
                ContractSession::begin(Request::Prefer(backend, profile))
                    .map(ContractSession::finish),
                Ok(Ok(Route::Portable(Some(Fallback {
                    backend,
                    profile,
                    reason: Error::NotOperational
                }))))
            );
        }
    }
}

#[test]
fn exhaustive_selection_table_preserves_exact_identity_and_fallback() {
    for backend in Backend::ALL {
        for profile in [Profile::Ordinary, Profile::Hardened] {
            for bits in 0..32 {
                let expected = if bits & 16 == 0 {
                    Some(Error::Quarantined)
                } else if bits & 3 != 3 {
                    Some(Error::NotOperational)
                } else if bits & 4 == 0 {
                    Some(Error::UnsupportedPlatform)
                } else if profile == Profile::Hardened && bits & 8 == 0 {
                    Some(Error::UnsupportedProfile)
                } else {
                    None
                };
                assert_eq!(
                    ContractSession::select(Request::Portable, flags(bits))
                        .map(ContractSession::finish),
                    Ok(Ok(Route::Portable(None)))
                );
                for prefer in [false, true] {
                    let request = if prefer {
                        Request::Prefer(backend, profile)
                    } else {
                        Request::Require(backend, profile)
                    };
                    let actual =
                        ContractSession::select(request, flags(bits)).map(ContractSession::finish);
                    let wanted = match expected {
                        None => Ok(Ok(Route::Accelerated(backend, profile))),
                        Some(Error::Quarantined) => Err(Error::Quarantined),
                        Some(reason) if prefer => Ok(Ok(Route::Portable(Some(Fallback {
                            backend,
                            profile,
                            reason,
                        })))),
                        Some(reason) => Err(reason),
                    };
                    assert_eq!(actual, wanted);
                }
            }
        }
    }
}

#[test]
fn established_prefer_and_require_never_downgrade_after_health_loss() -> Result<(), Error> {
    for backend in Backend::ALL {
        for request in [
            Request::Prefer(backend, Profile::Ordinary),
            Request::Require(backend, Profile::Hardened),
        ] {
            for integrity in [false, true] {
                let mut session = ContractSession::select(request, flags(31))?;
                session.fail_closed(integrity);
                let first = if integrity {
                    Error::Quarantined
                } else {
                    Error::AuthorityLost
                };
                assert_eq!(session.route(), Err(first));
                session.fail_closed(!integrity);
                assert_eq!(session.finish(), Err(first));
            }
        }
    }
    Ok(())
}
