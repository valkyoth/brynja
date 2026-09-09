//! Explicit hosted selection for ordinary raw kernels, not complete hashes.
//!
//! Default hash constructors and the facade remain portable. Only documented
//! system-wide AArch64 feature APIs authorize this hosted route. Generic x86,
//! BSD and unknown platforms fail closed: current-core flags alone cannot
//! establish migration safety. Target-specialized binaries can separately use
//! `brynja_crypto_cpu::static_execution`. No affinity or global policy changes.

use brynja_crypto_cpu::runtime_execution::Authority as KernelAuthority;
pub use brynja_crypto_cpu::runtime_execution::{
    Error as KernelError, Health, Kernel, PublicData, Session,
};

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
mod features;
mod platform;

/// Explicit caller preference; no automatic process-global installation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Do not probe or execute a kernel. The consumer performs portable work.
    Portable,
    /// Fall back only for pre-execution unavailability. Kernel failures never
    /// authorize fallback, including failed startup tests and quarantine.
    Prefer,
    /// Reject unavailable acceleration rather than silently choosing portable.
    Require,
}

/// Why no hosted execution permit could be created.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Unavailable {
    /// Kernel and host architectures differ.
    WrongArchitecture,
    /// The supported detector did not establish the complete CPU/OS bundle.
    MissingFeaturesOrOsState,
    /// No reviewed all-schedulable-CPU guarantee; affinity is not assumed.
    MissingMigrationGuarantee,
}

/// Observable selected route. A copied report is not an execution permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    /// Caller explicitly requested portable execution.
    PortableRequested,
    /// Preferred acceleration was unavailable before any kernel execution.
    PortableFallback(Unavailable),
    /// A platform-authorized kernel owner exists; inspect current health.
    Accelerated,
}

/// Failure to select or use a hosted owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Required acceleration was unavailable; no portable replacement exists.
    Unavailable(Unavailable),
    /// Existing kernel owner rejected the operation; no fallback is allowed.
    Kernel(KernelError),
}

/// Secret-free selection and live health observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Report {
    /// Requested kernel identity, even when the portable route was selected.
    pub kernel: Kernel,
    /// Immutable route selected at construction.
    pub route: Route,
    /// Actual current owner health, absent on a portable route.
    pub health: Option<Health>,
}

/// Sealed caller-owned selection. Not cloneable, Send, Sync or resettable.
///
/// No caller-supplied detector, feature mask or copied report can mint a permit.
/// New owners make a fresh selection; they do not revive old sessions. Failure
/// is owner-local, not a process-wide or FIPS-module quarantine guarantee.
///
/// ```
/// use brynja_crypto_cpu_std::execution::{Authority, Kernel, Mode, Route};
/// let owner = Authority::new(Kernel::ArmSha256, Mode::Portable)?;
/// assert_eq!(owner.report().route, Route::PortableRequested);
/// assert!(owner.session()?.is_none()); // consumer uses its portable algorithm
/// # Ok::<(), brynja_crypto_cpu_std::execution::Error>(())
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu_std::execution::Authority;
/// fn send<T: Send>() {}
/// send::<Authority>();
/// ```
pub struct Authority {
    kernel: Kernel,
    route: Route,
    owner: Option<KernelAuthority>,
}

impl Authority {
    /// Selects using the platform detector. Portable mode never probes.
    /// A startup failure retains a quarantined owner, never a fallback route;
    /// [`Self::session`] then returns an error even in preferred mode.
    pub fn new(kernel: Kernel, mode: Mode) -> Result<Self, Error> {
        Self::select(kernel, mode, || platform::construct(kernel))
    }

    fn select(
        kernel: Kernel,
        mode: Mode,
        construct: impl FnOnce() -> Result<KernelAuthority, Error>,
    ) -> Result<Self, Error> {
        if mode == Mode::Portable {
            return Ok(Self {
                kernel,
                route: Route::PortableRequested,
                owner: None,
            });
        }
        // Selection and authorization share one private availability decision.
        // Only pre-instruction unavailability can choose a portable fallback.
        let (route, owner) = match construct() {
            Ok(owner) => (Route::Accelerated, Some(owner)),
            Err(Error::Unavailable(reason)) => (choose(mode, Err(reason))?, None),
            Err(error) => return Err(error),
        };
        Ok(Self {
            kernel,
            route,
            owner,
        })
    }

    /// Reports the current health; retained reports cannot re-enable a session.
    pub fn report(&self) -> Report {
        Report {
            kernel: self.kernel,
            route: self.route,
            health: self.owner.as_ref().map(|owner| owner.report().health),
        }
    }

    /// `None` means the explicitly reported portable route. Kernel errors must
    /// not be interpreted as permission to continue using a different backend.
    pub fn session(&self) -> Result<Option<Session<'_>>, Error> {
        self.owner
            .as_ref()
            .map(KernelAuthority::session)
            .transpose()
            .map_err(Error::Kernel)
    }

    /// Permanently quarantines this kernel owner and every borrowed session.
    /// Portable selections have no kernel owner and remain portable.
    pub fn quarantine(&self) {
        if let Some(owner) = &self.owner {
            owner.quarantine();
        }
    }
}

fn choose(mode: Mode, availability: Result<(), Unavailable>) -> Result<Route, Error> {
    if mode == Mode::Portable {
        return Ok(Route::PortableRequested);
    }
    match availability {
        Ok(()) => Ok(Route::Accelerated),
        Err(reason) if mode == Mode::Prefer => Ok(Route::PortableFallback(reason)),
        Err(reason) => Err(Error::Unavailable(reason)),
    }
}

#[cfg(test)]
mod tests;
