use super::{Error, Kernel};
use brynja_crypto_cpu::static_execution as raw;

/// Explicit target-specialized selection. No host probing or global install.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Always use the portable permutation.
    Portable,
    /// Fall back only for pre-execution feature/architecture unavailability.
    Prefer,
    /// Require the requested complete kernel feature bundle.
    Require,
}

/// Immutable observation, not an execution authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    /// Explicit portable execution; hosted fallback details remain in its owner.
    Portable,
    /// Target-specialized execution was unavailable before entry.
    StaticFallback(raw::Error),
    /// Compiler-authorized, deployment-specialized permutation.
    Static(Kernel),
    /// Platform-authorized permutation borrowed from a hosted owner.
    Runtime(Kernel),
}

/// Retained selection. Target features must be valid on every deployment CPU.
pub struct StaticSelection {
    owner: Option<raw::Authority>,
    route: Route,
}

impl StaticSelection {
    /// Selects once; a wrong operation or startup failure never falls back.
    pub fn new(kernel: Kernel, mode: Mode) -> Result<Self, Error> {
        check_kernel(kernel)?;
        if mode == Mode::Portable {
            return Ok(Self {
                owner: None,
                route: Route::Portable,
            });
        }
        match raw::Authority::new(kernel) {
            Ok(owner) => {
                owner.session()?;
                Ok(Self {
                    owner: Some(owner),
                    route: Route::Static(kernel),
                })
            }
            Err(reason @ (raw::Error::WrongArchitecture | raw::Error::MissingTargetFeatures))
                if mode == Mode::Prefer =>
            {
                Ok(Self {
                    owner: None,
                    route: Route::StaticFallback(reason),
                })
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Borrows the selected healthy route into one absorbing state or reader.
    pub fn execution(&self) -> Result<Execution<'_>, Error> {
        Ok(Execution {
            route: self.route,
            inner: match &self.owner {
                Some(owner) => Inner::Static(owner.session()?),
                None => Inner::Portable,
            },
        })
    }

    /// Permanently invalidates this accelerated owner and every borrowed reader.
    pub fn quarantine(&self) {
        if let Some(owner) = &self.owner {
            owner.quarantine();
        }
    }
}

enum Inner<'a> {
    Portable,
    #[cfg(test)]
    Fault(core::cell::Cell<usize>),
    Static(raw::Session<'a>),
    #[cfg(feature = "runtime-execution")]
    Runtime(brynja_crypto_cpu::runtime_execution::Session<'a>),
}

/// Sealed borrowed route, neither Clone nor Send/Sync. Public data only.
/// Thread binding does not prevent OS scheduling or VM migration.
pub struct Execution<'a> {
    route: Route,
    inner: Inner<'a>,
}

impl<'a> Execution<'a> {
    #[cfg(test)]
    pub(super) fn fault_after(permutations: usize) -> Self {
        Self {
            route: Route::Portable,
            inner: Inner::Fault(core::cell::Cell::new(permutations)),
        }
    }
    /// No CPU discovery or accelerated instruction entry.
    #[must_use]
    pub const fn portable() -> Self {
        Self {
            route: Route::Portable,
            inner: Inner::Portable,
        }
    }

    /// Borrows a compiler-authorized Keccak owner; reports cannot mint a route.
    pub fn from_static(owner: &'a raw::Authority) -> Result<Self, Error> {
        check_kernel(owner.report().kernel)?;
        Ok(Self {
            route: Route::Static(owner.report().kernel),
            inner: Inner::Static(owner.session()?),
        })
    }

    /// Borrows a platform-authorized session from the separate hosted crate.
    #[cfg(feature = "runtime-execution")]
    pub fn from_runtime(
        session: brynja_crypto_cpu::runtime_execution::Session<'a>,
    ) -> Result<Self, Error> {
        let execution = Self {
            route: Route::Runtime(session.report().kernel),
            inner: Inner::Runtime(session),
        };
        execution.check()?;
        Ok(execution)
    }

    /// Selected route, never independent verification or a health certificate.
    #[must_use]
    pub const fn route(&self) -> Route {
        self.route
    }

    pub(super) fn check(&self) -> Result<(), Error> {
        let report = match &self.inner {
            Inner::Portable => return Ok(()),
            #[cfg(test)]
            Inner::Fault(_) => return Ok(()),
            Inner::Static(session) => session.report(),
            #[cfg(feature = "runtime-execution")]
            Inner::Runtime(session) => session.report(),
        };
        match report.health {
            raw::Health::Healthy => check_kernel(report.kernel),
            raw::Health::Testing => Err(raw::Error::NotReady.into()),
            raw::Health::Quarantined => Err(raw::Error::Quarantined.into()),
        }
    }

    pub(super) fn permute(&self, state: &mut [u64; 25]) -> Result<(), Error> {
        match &self.inner {
            Inner::Portable => crate::keccak::permute(state),
            #[cfg(test)]
            Inner::Fault(remaining) => {
                if remaining.get() == 0 {
                    return Err(raw::Error::Quarantined.into());
                }
                remaining.set(remaining.get().saturating_sub(1));
                crate::keccak::permute(state);
            }
            Inner::Static(session) => session.permute_keccak(raw::PublicData::new(state))?,
            #[cfg(feature = "runtime-execution")]
            Inner::Runtime(session) => session.permute_keccak(raw::PublicData::new(state))?,
        }
        Ok(())
    }
}

fn check_kernel(kernel: Kernel) -> Result<(), Error> {
    match kernel {
        Kernel::X86Keccak | Kernel::ArmKeccak => Ok(()),
        _ => Err(raw::Error::WrongOperation.into()),
    }
}
