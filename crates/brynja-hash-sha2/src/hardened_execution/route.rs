use super::{Error, Route};
use crate::hardened::{HardenedSha2Owner, compress32, compress64};
use brynja_crypto_cpu::{hardened_execution as cpu, static_execution as raw};

// Fixed caller-owned storage is intentional: no allocation/Box in this leaf.
#[allow(clippy::large_enum_variant)]
enum Inner<'a> {
    Portable,
    Cpu(cpu::Session<'a>),
}

/// Sealed, affine route that cannot be forged from an ordinary/public hash state.
pub struct Execution<'a> {
    route: Route,
    inner: Inner<'a>,
}

impl<'a> Execution<'a> {
    /// Uses the existing owner-backed portable compression without CPU probing.
    #[must_use]
    pub const fn portable() -> Self {
        Self {
            route: Route::Portable,
            inner: Inner::Portable,
        }
    }
    /// Borrow a complete static authority; runs the real hardened-kernel KAT.
    pub fn from_static(owner: &'a raw::Authority) -> Result<Self, Error> {
        Ok(Self {
            route: Route::Static(owner.report().kernel),
            inner: Inner::Cpu(cpu::Session::from_static(owner)?),
        })
    }
    /// Borrow a hosted authority; never convert its errors to portable fallback.
    #[cfg(feature = "runtime-execution")]
    pub fn from_runtime(
        session: brynja_crypto_cpu::runtime_execution::Session<'a>,
    ) -> Result<Self, Error> {
        Ok(Self {
            route: Route::Runtime(session.report().kernel),
            inner: Inner::Cpu(cpu::Session::from_runtime(session)?),
        })
    }
    /// Public selected-route observation.
    #[must_use]
    pub const fn route(&self) -> Route {
        self.route
    }
    pub(crate) fn fallback(route: Route) -> Self {
        Self {
            route,
            inner: Inner::Portable,
        }
    }
    pub(super) fn check(&self, wide: bool) -> Result<(), Error> {
        match &self.inner {
            Inner::Portable => Ok(()),
            Inner::Cpu(session) => session.check(wide).map_err(Error::from),
        }
    }
    pub(super) fn compress(
        &mut self,
        wide: bool,
        owner: &mut HardenedSha2Owner,
    ) -> Result<(), Error> {
        match &mut self.inner {
            Inner::Portable => {
                if wide {
                    compress64::compress(owner);
                } else {
                    compress32::compress(owner);
                }
            }
            Inner::Cpu(session) => {
                session.compress(wide, &mut owner.chaining_state, &owner.block_copy)?
            }
        }
        owner.wipe_compression_scratch();
        Ok(())
    }
}
