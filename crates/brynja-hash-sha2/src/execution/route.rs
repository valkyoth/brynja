use super::{Error, Kernel, PublicData};
use brynja_crypto_cpu::static_execution as raw;

/// Explicit static selection policy; hosted policy is provided by the std adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Do not construct or execute an accelerated owner.
    Portable,
    /// Fall back only if the complete compiler feature bundle is unavailable.
    Prefer,
    /// Require the selected kernel; never replace failures with portable work.
    Require,
}

/// Public observation, never an authority or a proof of CPU migration safety.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    /// Explicit portable route (hosted fallback details stay in its owner report).
    Portable,
    /// Static selection unavailable before instruction entry.
    StaticFallback(raw::Error),
    /// Complete target-specialized kernel route.
    Static(Kernel),
    /// Lifetime-wide platform-authorized kernel route.
    Runtime(Kernel),
}

/// Retained static selection. Target features must be deployment-safe on every CPU.
pub struct StaticSelection {
    owner: Option<raw::Authority>,
    route: Route,
}

impl StaticSelection {
    /// Selects once. Startup health failures cannot authorize portable fallback.
    pub fn new(kernel: Kernel, mode: Mode) -> Result<Self, Error> {
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

    /// Borrows a route; construction and every update/finalization check health.
    pub fn execution(&self) -> Result<Execution<'_>, Error> {
        Ok(Execution {
            route: self.route,
            inner: match &self.owner {
                Some(owner) => Inner::Static(owner.session()?),
                None => Inner::Portable,
            },
        })
    }

    /// Borrows the same selection through the separate erasing SHA-2 kernels.
    /// A failed hardened startup KAT never becomes a portable fallback.
    #[cfg(feature = "hardened-execution")]
    pub fn hardened_execution(
        &self,
    ) -> Result<crate::hardened_execution::Execution<'_>, crate::hardened_execution::Error> {
        match &self.owner {
            Some(owner) => crate::hardened_execution::Execution::from_static(owner),
            None => Ok(crate::hardened_execution::Execution::fallback(self.route)),
        }
    }

    /// Irreversibly invalidates this selected accelerated owner and all streams.
    pub fn quarantine(&self) {
        if let Some(owner) = &self.owner {
            owner.quarantine();
        }
    }
}

enum Inner<'a> {
    Portable,
    Static(raw::Session<'a>),
    #[cfg(feature = "runtime-execution")]
    Runtime(brynja_crypto_cpu::runtime_execution::Session<'a>),
}

/// Borrowed route moved into exactly one hash stream. No callbacks or forged providers.
///
/// Neither streams nor execution routes are Send/Sync. OS/hypervisor ABI
/// guarantees are still necessary; thread-bound ownership cannot stop migration.
pub struct Execution<'a> {
    route: Route,
    inner: Inner<'a>,
}

impl<'a> Execution<'a> {
    /// Explicitly selects the portable algorithm without instruction probing.
    #[must_use]
    pub const fn portable() -> Self {
        Self {
            route: Route::Portable,
            inner: Inner::Portable,
        }
    }

    /// Uses an already-created static authority. No report can mint this route.
    pub fn from_static(owner: &'a raw::Authority) -> Result<Self, Error> {
        Ok(Self {
            route: Route::Static(owner.report().kernel),
            inner: Inner::Static(owner.session()?),
        })
    }

    /// Uses a borrowed runtime session from the separately selected hosted owner.
    /// Call `owner.session()?` first; never turn an error into `portable()`.
    #[cfg(feature = "runtime-execution")]
    #[must_use]
    pub fn from_runtime(session: brynja_crypto_cpu::runtime_execution::Session<'a>) -> Self {
        Self {
            route: Route::Runtime(session.report().kernel),
            inner: Inner::Runtime(session),
        }
    }

    /// Immutable route observation; no claim that padding/IV setup is vectorized.
    #[must_use]
    pub const fn route(&self) -> Route {
        self.route
    }

    pub(crate) fn check(&self, wide: bool) -> Result<(), Error> {
        let report = match &self.inner {
            Inner::Portable => return Ok(()),
            Inner::Static(session) => session.report(),
            #[cfg(feature = "runtime-execution")]
            Inner::Runtime(session) => session.report(),
        };
        match report.health {
            raw::Health::Healthy => {}
            raw::Health::Testing => return Err(raw::Error::NotReady.into()),
            raw::Health::Quarantined => return Err(raw::Error::Quarantined.into()),
        }
        match (wide, report.kernel) {
            (false, Kernel::X86Sha256 | Kernel::ArmSha256) | (true, Kernel::ArmSha512) => Ok(()),
            _ => Err(raw::Error::WrongOperation.into()),
        }
    }

    pub(crate) fn compress32(&self, state: &mut [u32; 8], block: &[u8; 64]) -> Result<(), Error> {
        match &self.inner {
            Inner::Portable => crate::compress::compress(state, block),
            Inner::Static(session) => {
                session.compress_sha256(PublicData::new(state), PublicData::new(block))?
            }
            #[cfg(feature = "runtime-execution")]
            Inner::Runtime(session) => {
                session.compress_sha256(PublicData::new(state), PublicData::new(block))?
            }
        }
        Ok(())
    }

    pub(crate) fn compress64(&self, state: &mut [u64; 8], block: &[u8; 128]) -> Result<(), Error> {
        match &self.inner {
            Inner::Portable => crate::compress64::compress(state, block),
            Inner::Static(session) => {
                session.compress_sha512(PublicData::new(state), PublicData::new(block))?
            }
            #[cfg(feature = "runtime-execution")]
            Inner::Runtime(session) => {
                session.compress_sha512(PublicData::new(state), PublicData::new(block))?
            }
        }
        Ok(())
    }
}
