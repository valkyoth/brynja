//! Opt-in ordinary kernel execution for target-specialized `no_std` binaries.
//!
//! Cargo's `static-execution` feature exposes the API, not CPU support. The
//! compiler must enable every required target feature. Deployment must ensure
//! compatible CPUs and OS register state throughout execution, including CPU
//! migration and VM changes. Thread-bound ownership is not migration protection.
//! No runtime probing, global state, allocation or hardened secret processing.
//! Raw compression/permutation is not a complete hash API or authentication.

use core::{cell::Cell, marker::PhantomData};

mod kernel;
mod public_data;
pub use public_data::PublicData;
mod operations;
pub use kernel::Kernel;

/// Closed static execution failure; never a request to silently switch routes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// This kernel belongs to a different architecture.
    WrongArchitecture,
    /// The executable's compiler feature bundle is incomplete.
    MissingTargetFeatures,
    /// The operation does not match the authority's kernel.
    WrongOperation,
    /// Startup testing is incomplete; no session or operation is permitted.
    /// Synchronous public construction never exposes this internal state.
    NotReady,
    /// Startup testing failed or the owner was permanently invalidated.
    Quarantined,
    /// The borrowed session no longer matches its owner's health generation.
    StaleGeneration,
}

/// Diagnostic health, not a capability or proof of independent verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Health {
    /// Direct kernel startup testing is in progress; sessions cannot be obtained.
    Testing,
    /// Direct startup testing passed for this owner.
    Healthy,
    /// Irreversible failure for this owner and all its borrowed sessions.
    Quarantined,
}

/// Non-authorizing public observation of the exact owner and generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Report {
    /// Exact kernel identity.
    pub kernel: Kernel,
    /// Current health.
    pub health: Health,
    /// Owner-local generation, not a global identifier.
    pub generation: u64,
}

/// Sealed caller-owned authority; no clone, reset or caller attestation.
///
/// A failed KAT returns a quarantined owner so its failure can be retained.
/// Check [`Self::session`] before use; it rejects such an owner. Quarantine is
/// owner-local, not a process-wide or FIPS-module irreversible error state.
///
/// ```compile_fail
/// use brynja_crypto_cpu::static_execution::{Authority, Report};
/// fn forge(report: Report) -> Authority { report.into() }
/// ```
///
/// ```compile_fail
/// use brynja_crypto_cpu::static_execution::Authority;
/// fn require_send<T: Send>() {}
/// require_send::<Authority>();
/// ```
///
/// ```compile_fail
/// use brynja_crypto_cpu::static_execution::Authority;
/// fn require_clone<T: Clone>() {}
/// require_clone::<Authority>();
/// ```
/// Operations are synchronous and invoke no caller callbacks. These owners
/// are not signal-handler or async-reentrant interfaces; do not reenter an
/// operation through a signal handler or hook. Sequential same-thread calls
/// and explicit quarantine between calls are supported.
pub struct Authority {
    kernel: Kernel,
    health: Cell<Health>,
    generation: Cell<u64>,
    thread_bound: PhantomData<*mut ()>,
}

impl Authority {
    /// Checks the complete static bundle, then executes the actual kernel KAT.
    ///
    /// Feature/architecture errors occur before any instruction entry. The
    /// returned owner may be quarantined if the KAT failed; it cannot issue a
    /// session or be reset. Default hash constructors remain portable.
    pub fn new(kernel: Kernel) -> Result<Self, Error> {
        kernel.check_compiled_target()?;
        let owner = Self {
            kernel,
            health: Cell::new(Health::Testing),
            generation: Cell::new(1),
            thread_bound: PhantomData,
        };
        owner.complete_startup(operations::known_answer(kernel));
        Ok(owner)
    }

    fn complete_startup(&self, passed: bool) {
        self.generation.set(2);
        self.health.set(if passed {
            Health::Healthy
        } else {
            Health::Quarantined
        });
    }

    /// Reports health; the copied report cannot issue or renew a session.
    pub fn report(&self) -> Report {
        Report {
            kernel: self.kernel,
            health: self.health.get(),
            generation: self.generation.get(),
        }
    }

    /// Borrows a session tied to this exact owner and health generation.
    pub fn session(&self) -> Result<Session<'_>, Error> {
        self.check(self.generation.get())?;
        Ok(Session {
            owner: self,
            generation: self.generation.get(),
        })
    }

    /// Irreversibly invalidates every session from this owner; repeated calls
    /// are idempotent. There is no reinitialization or generation wraparound.
    pub fn quarantine(&self) {
        if self.health.get() != Health::Quarantined {
            self.health.set(Health::Quarantined);
            self.generation.set(3);
        }
    }

    fn check(&self, generation: u64) -> Result<(), Error> {
        match self.health.get() {
            Health::Healthy => {}
            Health::Testing => return Err(Error::NotReady),
            Health::Quarantined => return Err(Error::Quarantined),
        }
        if self.generation.get() != generation {
            return Err(Error::StaleGeneration);
        }
        self.kernel.check_compiled_target()
    }
}

/// Borrowed, non-cloneable authority for ordinary public-data kernel work.
///
/// Every operation rechecks its owner's health, generation and static bundle
/// before mutation. It cannot outlive or change owners. No secret-state cleanup
/// is provided; do not pass key-derived state, passwords or confidential data.
///
/// ```compile_fail
/// use brynja_crypto_cpu::static_execution::{Authority, Kernel, Session};
/// fn escape() -> Session<'static> {
///     Authority::new(Kernel::X86Sha256).unwrap().session().unwrap()
/// }
/// ```
pub struct Session<'a> {
    owner: &'a Authority,
    generation: u64,
}

impl Session<'_> {
    #[cfg(feature = "hardened-execution")]
    pub(crate) fn check_hardened(&self) -> Result<Kernel, Error> {
        self.owner.check(self.generation)?;
        Ok(self.owner.kernel)
    }

    #[cfg(feature = "hardened-execution")]
    pub(crate) fn quarantine_hardened(&self) {
        self.owner.quarantine();
    }

    /// Reports the current owner's health, not an execution permit.
    pub fn report(&self) -> Report {
        self.owner.report()
    }

    /// Compresses one SHA-256 block. Errors preserve the complete state.
    pub fn compress_sha256(
        &self,
        state: PublicData<&mut [u32; 8]>,
        block: PublicData<&[u8; 64]>,
    ) -> Result<(), Error> {
        self.owner.check(self.generation)?;
        operations::sha256(self.owner.kernel, state.into_inner(), block.into_inner())
    }

    /// Compresses one SHA-512-family block. Errors preserve the complete state.
    pub fn compress_sha512(
        &self,
        state: PublicData<&mut [u64; 8]>,
        block: PublicData<&[u8; 128]>,
    ) -> Result<(), Error> {
        self.owner.check(self.generation)?;
        operations::sha512(self.owner.kernel, state.into_inner(), block.into_inner())
    }

    /// Permutes a complete `Keccak-f[1600]` state. Errors preserve every lane.
    pub fn permute_keccak(&self, state: PublicData<&mut [u64; 25]>) -> Result<(), Error> {
        self.owner.check(self.generation)?;
        operations::keccak(self.owner.kernel, state.into_inner())
    }
}

#[cfg(test)]
mod tests;
