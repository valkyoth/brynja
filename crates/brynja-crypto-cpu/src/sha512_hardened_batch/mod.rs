//! Default-off clearing SHA-512-family multibuffer compression owners.
//!
//! Separate from ordinary batching: no public-data assertion or ordinary
//! workspace is accepted. This is a compression primitive, not a hash API.
//! Caller states/blocks remain caller-owned, including on failure. Only packed
//! operation storage is owned and erased here. Registers, compiler copies,
//! abort, forced termination and forgotten owners remain erasure limitations.

use core::{cell::Cell, marker::PhantomData};
#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
mod arm;
mod platform;
mod scratch;
#[cfg(target_arch = "x86_64")]
mod x86;
pub use scratch::Workspace;

/// Exact hardened vector implementation, not historical candidate admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kernel {
    /// Four independent states, requiring AVX2 and OS-enabled YMM context.
    Avx2,
    /// Two independent states on little-endian AArch64 NEON.
    Neon,
}
impl Kernel {
    /// Active lanes; remaining caller states are preserved.
    pub const fn width(self) -> usize {
        match self {
            Self::Avx2 => 4,
            Self::Neon => 2,
        }
    }
    fn architecture(self) -> bool {
        match self {
            Self::Avx2 => cfg!(target_arch = "x86_64"),
            Self::Neon => cfg!(all(target_arch = "aarch64", target_endian = "little")),
        }
    }
    /// Build-wide bundle only; does not probe hardware or guarantee migration.
    pub const fn compiled(self) -> bool {
        match self {
            Self::Avx2 => cfg!(all(
                target_arch = "x86_64",
                target_feature = "avx",
                target_feature = "avx2"
            )),
            Self::Neon => cfg!(all(
                target_arch = "aarch64",
                target_endian = "little",
                target_feature = "neon"
            )),
        }
    }
}

/// Closed compression failure; none permits silent portable fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Kernel is incompatible with this target.
    WrongArchitecture,
    /// Static feature bundle is incomplete.
    MissingFeatures,
    /// Owner was revoked, or a startup/health check failed.
    Quarantined,
    /// Internal indexing or successful-call accounting failed.
    Invariant,
}

/// Thread-bound authority for the distinct clearing kernels.
/// Revalidation can revoke but cannot establish scheduling/migration safety.
/// Drop-based quarantine does not run under `panic = "abort"`.
///
/// ```compile_fail
/// use brynja_crypto_cpu::sha512_hardened_batch::Authority;
/// fn require<T: Send>() {}
/// require::<Authority>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu::sha512_hardened_batch::Authority;
/// fn require<T: Sync>() {}
/// require::<Authority>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu::sha512_hardened_batch::Authority;
/// fn require<T: Copy>() {}
/// require::<Authority>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu::sha512_hardened_batch::Authority;
/// fn require<T: Clone>() {}
/// require::<Authority>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu::sha512_hardened_batch::Authority;
/// fn require<T: core::fmt::Debug>() {}
/// require::<Authority>();
/// ```
pub struct Authority {
    kernel: Kernel,
    healthy: Cell<bool>,
    completed: Cell<u64>,
    revalidate: fn(Kernel) -> bool,
    thread_bound: PhantomData<*mut ()>,
}
impl Authority {
    /// Selects a build-specialized kernel and runs its actual startup KAT.
    /// All CPUs used by the executable must support the build's complete bundle
    /// throughout this owner's lifetime. Otherwise use portable hashing.
    pub fn for_compiled_target(kernel: Kernel) -> Result<Self, Error> {
        if !kernel.architecture() {
            return Err(Error::WrongArchitecture);
        }
        if !kernel.compiled() {
            return Err(Error::MissingFeatures);
        }
        Self::create(kernel, Kernel::compiled)
    }
    fn create(kernel: Kernel, revalidate: fn(Kernel) -> bool) -> Result<Self, Error> {
        if !kernel.architecture() {
            return Err(Error::WrongArchitecture);
        }
        let owner = Self {
            kernel,
            healthy: Cell::new(true),
            completed: Cell::new(0),
            revalidate,
            thread_bound: PhantomData,
        };
        // Public startup input only. No confidential source aggregate is moved.
        let mut states = [crate::sha512::initial_state(); 4];
        let blocks = [crate::sha512::abc_block(); 4];
        let mut workspace = Workspace::new();
        owner
            .session()?
            .compress(&mut states, &blocks, &mut workspace)?;
        if !states
            .iter()
            .take(kernel.width())
            .all(|state| *state == crate::sha512::abc_digest_state())
        {
            owner.quarantine();
            return Err(Error::Quarantined);
        }
        owner.completed.set(0);
        Ok(owner)
    }
    /// Permanently revokes all sessions borrowed from this owner.
    pub fn quarantine(&self) {
        self.healthy.set(false);
    }
    /// Public health status only, not an authorization token.
    pub fn is_healthy(&self) -> bool {
        self.healthy.get()
    }
    /// Borrows a non-cloneable, lifetime-bound session.
    pub fn session(&self) -> Result<Session<'_>, Error> {
        self.check()?;
        Ok(Session { owner: self })
    }
    fn check(&self) -> Result<(), Error> {
        let mut guard = HealthGuard {
            owner: self,
            complete: false,
        };
        if !self.healthy.get() || !(self.revalidate)(self.kernel) {
            return Err(Error::Quarantined);
        }
        guard.complete = true;
        Ok(())
    }
}

/// Borrowed authority; cannot outlive or reopen its quarantined owner.
///
/// ```compile_fail
/// use brynja_crypto_cpu::sha512_hardened_batch::Session;
/// fn require<T: Send>() {}
/// require::<Session<'_>>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu::sha512_hardened_batch::Session;
/// fn require<T: Sync>() {}
/// require::<Session<'_>>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu::sha512_hardened_batch::Session;
/// fn require<T: Copy>() {}
/// require::<Session<'_>>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu::sha512_hardened_batch::Session;
/// fn require<T: Clone>() {}
/// require::<Session<'_>>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu::sha512_hardened_batch::Session;
/// fn require<T: core::fmt::Debug>() {}
/// require::<Session<'_>>();
/// ```
pub struct Session<'a> {
    owner: &'a Authority,
}
impl Session<'_> {
    /// Compresses canonical big-endian byte states without an unowned word array.
    /// Caller states/blocks remain caller-owned; all workspace regions clear on
    /// every exit. Inactive NEON slots and all states on error are preserved.
    pub fn compress_bytes(
        &self,
        states: &mut [[u8; 64]; 4],
        blocks: &[[u8; 128]; 4],
        workspace: &mut Workspace,
    ) -> Result<(), Error> {
        let mut operation = Operation {
            health: HealthGuard {
                owner: self.owner,
                complete: false,
            },
            workspace,
        };
        self.ensure_healthy()?;
        operation
            .workspace
            .pack_bytes(states, blocks, self.kernel().width())?;
        platform::dispatch(self.kernel(), operation.workspace)?;
        self.ensure_healthy()?;
        let completed = self
            .owner
            .completed
            .get()
            .checked_add(1)
            .ok_or(Error::Invariant)?;
        operation
            .workspace
            .commit_bytes(states, self.kernel().width());
        self.owner.completed.set(completed);
        operation.health.complete = true;
        Ok(())
    }
    /// Selected kernel identity.
    pub const fn kernel(&self) -> Kernel {
        self.owner.kernel
    }
    /// Actual successful vector calls, excluding the startup KAT.
    pub fn completed_vector_calls(&self) -> u64 {
        self.owner.completed.get()
    }
    /// Revalidates health; cached detection is not a live migration monitor.
    pub fn ensure_healthy(&self) -> Result<(), Error> {
        self.owner.check()
    }
    /// Permanently revokes all sessions sharing the owner.
    pub fn quarantine(&self) {
        self.owner.quarantine();
    }
    /// Compresses one block per active lane with transactional caller state.
    ///
    /// All packed workspace regions clear on success, error and recoverable
    /// unwind, including inactive capacity. Caller input/state copies remain
    /// caller-owned. No callbacks or fallible checks occur during output commit.
    pub fn compress(
        &self,
        states: &mut [[u64; 8]; 4],
        blocks: &[[u8; 128]; 4],
        workspace: &mut Workspace,
    ) -> Result<(), Error> {
        let mut operation = Operation {
            health: HealthGuard {
                owner: self.owner,
                complete: false,
            },
            workspace,
        };
        self.ensure_healthy()?;
        operation
            .workspace
            .pack(states, blocks, self.kernel().width())?;
        platform::dispatch(self.kernel(), operation.workspace)?;
        self.ensure_healthy()?;
        let completed = self
            .owner
            .completed
            .get()
            .checked_add(1)
            .ok_or(Error::Invariant)?;
        operation.workspace.commit(states, self.kernel().width());
        self.owner.completed.set(completed);
        operation.health.complete = true;
        Ok(())
    }
}
struct HealthGuard<'a> {
    owner: &'a Authority,
    complete: bool,
}
impl Drop for HealthGuard<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.owner.quarantine();
        }
    }
}
struct Operation<'a, 'w> {
    health: HealthGuard<'a>,
    workspace: &'w mut Workspace,
}
impl Drop for Operation<'_, '_> {
    fn drop(&mut self) {
        self.workspace.wipe();
    }
}

#[cfg(test)]
mod tests;
