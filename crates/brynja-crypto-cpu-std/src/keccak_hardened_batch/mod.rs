//! Default-off hosted hardened SHA-3/SHAKE/cSHAKE batching.
//!
//! Only distinct clearing owners are accepted. Lengths, identities and work are
//! public metadata. Generic x86 detection cannot establish migration safety:
//! AVX2 requires a matching build-wide bundle and deployment. Allowlisted
//! little-endian AArch64 hosts use their process-wide NEON feature ABI under a
//! conforming OS/hypervisor; cached detection is not a live migration monitor.
//! No affinity changes or global dispatch policy. Registers, compiler copies,
//! abort and forgotten owners remain erasure limitations.
//!
//! ```
//! use brynja_crypto_cpu_std::keccak_hardened_batch::{Authority, Error, Mode};
//! # fn main() -> Result<(), Error> {
//! let authority = Authority::new(Mode::Portable)?;
//! assert_eq!(authority.kernel()?, None);
//! let executor = authority.executor(1)?;
//! // Use digest_secret with this executor and its distinct clearing Workspace.
//! drop(executor);
//! # Ok(()) }
//! ```
use brynja_crypto_cpu::keccak_hardened_batch::Authority as CpuAuthority;
/// Leaf operation failures, separate from hosted selection failures.
pub use brynja_hash_sha3::hardened_batch::Error as ExecutionError;
pub use brynja_hash_sha3::hardened_batch::{
    Algorithm, CAPACITY, Control, Executor, Input, Kernel, Mode, Report, SecretBatchOutput,
    Sha3PublicDeclassification, Workspace,
};
mod platform;
#[cfg(test)]
mod tests;

/// Only initial unavailability permits prefer-mode portable selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// No supported complete platform/feature contract.
    Unavailable,
    /// Startup or authority failure; never permits fallback.
    Execution(ExecutionError),
}

/// Thread-bound hosted owner. Executors borrow this owner; no ordinary authority
/// or public-data marker can be converted into it.
///
/// ```compile_fail
/// use brynja_crypto_cpu_std::keccak_hardened_batch::Authority;
/// fn require<T: Send>() {}
/// require::<Authority>();
/// ```
///
/// ```compile_fail
/// use brynja_crypto_cpu_std::keccak_hardened_batch::Authority;
/// fn require<T: Sync>() {}
/// require::<Authority>();
/// ```
///
/// ```compile_fail
/// use brynja_crypto_cpu_std::keccak_hardened_batch::Authority;
/// fn require<T: Copy>() {}
/// require::<Authority>();
/// ```
///
/// ```compile_fail
/// use brynja_crypto_cpu_std::keccak_hardened_batch::Authority;
/// fn require<T: Clone>() {}
/// require::<Authority>();
/// ```
///
/// ```compile_fail
/// use brynja_crypto_cpu_std::keccak_hardened_batch::Authority;
/// fn require<T: core::fmt::Debug>() {}
/// require::<Authority>();
/// ```
///
/// ```compile_fail
/// use brynja_crypto_cpu_std::keccak_hardened_batch::{Authority, Executor, Mode};
/// fn escape() -> Executor<'static> {
///     let owner = Authority::new(Mode::Portable).unwrap();
///     owner.executor(1).unwrap()
/// }
/// ```
pub struct Authority {
    owner: Option<CpuAuthority>,
    mode: Mode,
}
impl Authority {
    /// Portable never probes. Prefer may choose portable only before execution,
    /// when the platform is unavailable, never after a startup/health failure.
    pub fn new(mode: Mode) -> Result<Self, Error> {
        Self::select(mode, platform::construct)
    }
    fn select(mode: Mode, construct: fn() -> Result<CpuAuthority, Error>) -> Result<Self, Error> {
        if mode == Mode::Portable {
            return Ok(Self { owner: None, mode });
        }
        let owner = match construct() {
            Ok(owner) => Some(owner),
            Err(Error::Unavailable) if mode == Mode::Prefer => None,
            Err(error) => return Err(error),
        };
        Ok(Self { owner, mode })
    }
    /// Selected vector kernel; does not authorize a new route after revocation.
    pub fn kernel(&self) -> Result<Option<Kernel>, Error> {
        self.owner
            .as_ref()
            .map(|owner| {
                owner
                    .session()
                    .map(|session| session.kernel())
                    .map_err(backend)
            })
            .transpose()
    }
    /// Borrows a hardened executor using a nonzero workload crossover threshold.
    /// It never substitutes an ordinary executor or recovers a failed authority.
    pub fn executor(&self, minimum_work: usize) -> Result<Executor<'_>, Error> {
        if minimum_work == 0 {
            return Err(Error::Execution(ExecutionError::InvalidSelection));
        }
        match &self.owner {
            Some(owner) => {
                Executor::with_session(owner.session().map_err(backend)?, self.mode, minimum_work)
                    .map_err(Error::Execution)
            }
            None => Ok(Executor::portable()),
        }
    }
    /// Permanently revokes the selected CPU authority and its borrowed executors.
    /// Portable selections have no CPU authority and are unaffected. Revoke an
    /// individual portable executor using Executor::quarantine instead.
    /// Drop-based operation quarantine requires recoverable unwinding, not abort.
    pub fn quarantine(&self) {
        if let Some(owner) = &self.owner {
            owner.quarantine();
        }
    }
}
fn backend(error: brynja_crypto_cpu::keccak_hardened_batch::Error) -> Error {
    Error::Execution(ExecutionError::Backend(error))
}
