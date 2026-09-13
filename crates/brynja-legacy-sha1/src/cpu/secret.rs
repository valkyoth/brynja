//! Separate secret-bearing authority; ordinary authority cannot be converted.
#![allow(unsafe_code)]

use super::{Sha1Backend, Sha1BackendError, Sha1BackendHealth};
use crate::owner::Sha1Owner;
use brynja_core::clear_owned_region;
use core::{cell::Cell, marker::PhantomData};

pub(crate) struct Scratch {
    pub(crate) lanes: [u8; 16],
}
impl Scratch {
    pub(crate) const fn new() -> Self {
        Self { lanes: [0; 16] }
    }
    #[inline(never)]
    pub(crate) fn wipe(&mut self) {
        let _ = clear_owned_region(&mut self.lanes);
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// Thread-bound authority for the separately cleanup-qualified SHA-1 kernels.
/// SHA-1 is collision-broken; this is not modern algorithm or FIPS admission.
/// No ordinary authority, boolean feature report, or secret state import is accepted.
/// The historical `Sha1Backend::is_admitted` candidate flag does not authorize
/// this separate operational API. Complete platform authority, hardened owned
/// storage, startup KAT and irreversible health are mandatory here. Neither
/// independent cryptographic verification nor FIPS validation is claimed.
pub struct Authority {
    backend: Sha1Backend,
    healthy: Cell<bool>,
    revalidate: fn(Sha1Backend) -> bool,
    _thread: PhantomData<*mut ()>,
}
impl Authority {
    /// Opts into a binary specialized for the complete instruction bundle.
    /// Deployment must preserve that bundle on every CPU executing the binary.
    /// **No runtime feature detection or migration protection is performed.**
    /// Revalidation only repeats a compile-time constant. Restrict scheduling,
    /// hotplug and migration to compatible CPUs for the entire binary lifetime;
    /// use portable execution when the deployment cannot guarantee this.
    pub fn for_compiled_target() -> Result<Self, Sha1BackendError> {
        let backend =
            super::session::compiled_backend().ok_or(Sha1BackendError::MissingFeatures)?;
        Self::create(backend, super::session::compiled_features)
    }

    /// Accepts an external platform's lifetime-wide instruction authority.
    ///
    /// # Safety
    /// The caller must guarantee the backend's complete feature bundle on every
    /// schedulable CPU for the owner's entire lifetime, including hotplug and VM
    /// migration. The truthful backend-specific callback must not panic. Cached
    /// feature detection is not live revocation and cannot close a scheduling race.
    /// A non-Send marker or current-core CPUID observation is insufficient.
    pub unsafe fn from_platform(
        backend: Sha1Backend,
        revalidate: fn(Sha1Backend) -> bool,
    ) -> Result<Self, Sha1BackendError> {
        Self::create(backend, revalidate)
    }

    fn create(
        backend: Sha1Backend,
        revalidate: fn(Sha1Backend) -> bool,
    ) -> Result<Self, Sha1BackendError> {
        super::session::require_architecture(backend)?;
        let authority = Self {
            backend,
            healthy: Cell::new(true),
            revalidate,
            _thread: PhantomData,
        };
        authority.ensure_healthy()?;
        // Public startup input, but execute the actual hardened kernel/owner path.
        let mut owner = Sha1Owner::new();
        owner.block[0] = b'a';
        owner.block[1] = b'b';
        owner.block[2] = b'c';
        owner.block[3] = 0x80;
        owner.block[63] = 24;
        authority.compress(&mut owner)?;
        if owner.chaining_state
            != [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
            ]
        {
            authority.quarantine();
            return Err(Sha1BackendError::Quarantined);
        }
        Ok(authority)
    }

    /// Non-authorizing kernel identity.
    pub const fn backend(&self) -> Sha1Backend {
        self.backend
    }
    /// Current irreversible owner health; not a fresh OS feature observation.
    pub fn health(&self) -> Sha1BackendHealth {
        if self.healthy.get() {
            Sha1BackendHealth::Healthy
        } else {
            Sha1BackendHealth::Quarantined
        }
    }
    /// Permanently revokes this authority and all borrowed streams.
    pub fn quarantine(&self) {
        self.healthy.set(false);
    }
    pub(crate) fn ensure_healthy(&self) -> Result<(), Sha1BackendError> {
        if !self.healthy.get() {
            return Err(Sha1BackendError::Quarantined);
        }
        // Remain revoked if an external callback violates its no-unwind contract.
        self.healthy.set(false);
        if !(self.revalidate)(self.backend) {
            return Err(Sha1BackendError::MissingFeatures);
        }
        self.healthy.set(true);
        Ok(())
    }

    pub(crate) fn compress(&self, owner: &mut Sha1Owner) -> Result<(), Sha1BackendError> {
        let mut operation = Operation {
            authority: self,
            owner,
            completed: false,
        };
        self.ensure_healthy()?;
        let mut scratch = Scratch::new();
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if self.backend == Sha1Backend::X86Sha {
            // SAFETY: The lifetime-wide authority covers SHA/SSE2; health was
            // rechecked before this call. The kernel uses only owned exact arrays.
            unsafe {
                super::x86_sha1::compress_secret(operation.owner, &mut scratch)?;
            }
            operation.owner.clear_block();
            operation.completed = true;
            return Ok(());
        }
        #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
        if self.backend == Sha1Backend::Aarch64Sha1 {
            // SAFETY: The same lifetime-wide authority covers NEON/SHA2. All
            // loads and stores borrow exact live arrays inside these owners.
            unsafe {
                super::aarch64_sha1::compress_secret(operation.owner, &mut scratch)?;
            }
            operation.owner.clear_block();
            operation.completed = true;
            return Ok(());
        }
        let _ = &mut scratch;
        let _ = &mut operation;
        Err(Sha1BackendError::WrongArchitecture)
    }
}

struct Operation<'a> {
    authority: &'a Authority,
    owner: &'a mut Sha1Owner,
    completed: bool,
}
impl Drop for Operation<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.wipe();
            self.authority.quarantine();
        }
    }
}

#[cfg(test)]
mod tests;
