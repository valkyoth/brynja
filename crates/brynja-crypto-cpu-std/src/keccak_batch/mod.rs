//! Default-off hosted independent-message SHA-3/SHAKE/cSHAKE batching.
//!
//! Portable mode never probes. Generic x86 CPUID alone does not establish the
//! lifetime migration contract, so x86 requires a target-specialized binary.
//! Allowlisted AArch64 system feature APIs establish the process ABI under a
//! conforming OS/hypervisor; cached detection is not a live migration monitor.
//! No affinity changes, global policy, allocation or secret processing.

use brynja_crypto_cpu::keccak_batch::Authority as CpuAuthority;
pub use brynja_hash_sha3::batch::{
    Algorithm, Control, Executor, Input, Kernel, Mode, PublicData, Report, Workspace,
};
mod platform;
#[cfg(test)]
mod tests;

/// Selection or execution failure; only unavailability permits prefer fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Unsupported platform or absent complete feature/OS contract.
    Unavailable,
    /// Startup KAT, health or execution failure; never falls back.
    Execution(brynja_hash_sha3::batch::Error),
}

/// Sealed hosted selection. Its borrowed executors cannot outlive this owner.
pub struct Authority {
    owner: Option<CpuAuthority>,
    mode: Mode,
}
impl Authority {
    /// Selects explicitly; default SHA-3 APIs remain unchanged and portable.
    pub fn new(mode: Mode) -> Result<Self, Error> {
        if mode == Mode::Portable {
            return Ok(Self { owner: None, mode });
        }
        let owner = match platform::construct() {
            Ok(owner) => Some(owner),
            Err(Error::Unavailable) if mode == Mode::Prefer => None,
            Err(error) => return Err(error),
        };
        Ok(Self { owner, mode })
    }
    /// Returns the selected kernel, or None for requested/unavailable portable.
    pub fn kernel(&self) -> Result<Option<Kernel>, Error> {
        self.owner
            .as_ref()
            .map(|owner| owner.session().map(|s| s.kernel()).map_err(backend))
            .transpose()
    }
    /// Creates a borrowed workload executor with an explicit measured threshold.
    /// No existing owner's failure is converted into portable fallback.
    pub fn executor(&self, minimum_permutations: usize) -> Result<Executor<'_>, Error> {
        if minimum_permutations == 0 {
            return Err(Error::Execution(
                brynja_hash_sha3::batch::Error::InvalidSelection,
            ));
        }
        match &self.owner {
            Some(owner) => Executor::with_session(
                owner.session().map_err(backend)?,
                self.mode,
                minimum_permutations,
            )
            .map_err(Error::Execution),
            None => Ok(Executor::portable()),
        }
    }
    /// Permanently revokes every executor borrowed from this owner.
    pub fn quarantine(&self) {
        if let Some(owner) = &self.owner {
            owner.quarantine();
        }
    }
}

fn backend(error: brynja_crypto_cpu::keccak_batch::Error) -> Error {
    Error::Execution(brynja_hash_sha3::batch::Error::Backend(error))
}
