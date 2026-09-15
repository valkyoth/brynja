//! Default-off independent-message SHA-512-family SIMD compression.
//!
//! Ordinary/public data only: no erasure, hashing, padding or secret ownership.
//! AVX2 processes four lanes; NEON processes the first two (leaving the rest
//! unchanged). Static target support is a deployment obligation, not probing.
//! This operational profile is separate from historical candidate admission.

pub use crate::static_execution::PublicData;
use core::{cell::Cell, marker::PhantomData};

#[cfg(target_arch = "aarch64")]
mod arm;
mod platform;
#[cfg(target_arch = "x86_64")]
mod x86;

/// Exact vector kernel; not a dedicated single-stream SHA instruction route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kernel {
    /// Four independent 64-bit word lanes; AVX2 and OS-enabled YMM required.
    Avx2,
    /// Two independent 64-bit word lanes; AArch64 NEON required.
    Neon,
}

impl Kernel {
    /// Number of simultaneously compressed blocks.
    pub const fn width(self) -> usize {
        match self {
            Self::Avx2 => 4,
            Self::Neon => 2,
        }
    }

    pub(super) fn architecture(self) -> bool {
        match self {
            Self::Avx2 => cfg!(target_arch = "x86_64"),
            Self::Neon => cfg!(target_arch = "aarch64"),
        }
    }

    /// Complete compile-time bundle. Does not inspect the running machine.
    pub const fn compiled(self) -> bool {
        match self {
            Self::Avx2 => cfg!(all(
                target_arch = "x86_64",
                target_feature = "avx",
                target_feature = "avx2"
            )),
            Self::Neon => cfg!(all(target_arch = "aarch64", target_feature = "neon")),
        }
    }
}

/// Closed execution failure. No error authorizes portable fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Kernel belongs to a different architecture.
    WrongArchitecture,
    /// Static target bundle is incomplete.
    MissingFeatures,
    /// Startup KAT, revalidation, operation or unwind invalidated the owner.
    Quarantined,
    /// A fixed-size internal invariant was violated.
    Invariant,
}

/// Sealed, thread-bound owner. Quarantine is permanent and owner-local.
/// Neither feature detection nor startup KAT proves migration safety.
/// Quarantine on panic requires stack unwinding. With `panic = "abort"`, Drop
/// does not run: no explicit quarantine or cleanup is promised before termination.
///
/// ```compile_fail
/// use brynja_crypto_cpu::sha512_batch::Authority;
/// fn send<T: Send>() {} send::<Authority>();
/// ```
pub struct Authority {
    kernel: Kernel,
    healthy: Cell<bool>,
    completed_calls: Cell<u64>,
    revalidate: fn(Kernel) -> bool,
    thread_bound: PhantomData<*mut ()>,
}

impl Authority {
    /// Creates a target-specialized owner and runs the actual vector KAT.
    /// Every CPU used by this executable must support its compiled bundle.
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
            completed_calls: Cell::new(0),
            revalidate,
            thread_bound: PhantomData,
        };
        let mut states = core::hint::black_box([crate::sha512::initial_state(); 4]);
        let blocks = core::hint::black_box([crate::sha512::abc_block(); 4]);
        owner
            .session()?
            .compress(PublicData::new(&mut states), PublicData::new(&blocks))?;
        if !states
            .iter()
            .take(kernel.width())
            .all(|state| *state == crate::sha512::abc_digest_state())
        {
            owner.quarantine();
            return Err(Error::Quarantined);
        }
        owner.completed_calls.set(0);
        Ok(owner)
    }

    /// Permanently revokes all borrowed sessions. No reset or global effect.
    pub fn quarantine(&self) {
        self.healthy.set(false);
    }

    /// Current health, not an authorization capability.
    pub fn is_healthy(&self) -> bool {
        self.healthy.get()
    }

    /// Borrows authority; no owned copy or lifetime escape is possible.
    pub fn session(&self) -> Result<Session<'_>, Error> {
        self.check()?;
        Ok(Session { owner: self })
    }

    fn check(&self) -> Result<(), Error> {
        let mut guard = Operation {
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

/// Exclusive-lifetime provenance through a borrowed, non-cloneable session.
/// Raw states and blocks must both be classified public at every call.
pub struct Session<'a> {
    owner: &'a Authority,
}

impl Session<'_> {
    /// Successful vector dispatches on this owner, excluding its startup KAT.
    /// Overflow fails closed; this counter is public diagnostic data, not a permit.
    pub fn completed_vector_calls(&self) -> u64 {
        self.owner.completed_calls.get()
    }
    /// Exact vector identity.
    pub const fn kernel(&self) -> Kernel {
        self.owner.kernel
    }
    /// Revalidates health. Cached platform detection is not live revocation.
    pub fn ensure_healthy(&self) -> Result<(), Error> {
        self.owner.check()
    }
    /// Permanently revokes the owner, including all other sessions.
    pub fn quarantine(&self) {
        self.owner.quarantine();
    }
    /// Compresses one block per active kernel lane; preserves every state on error.
    /// NEON leaves slots two through three unchanged. No secret-state clearing.
    pub fn compress(
        &self,
        states: PublicData<&mut [[u64; 8]; 4]>,
        blocks: PublicData<&[[u8; 128]; 4]>,
    ) -> Result<(), Error> {
        let mut guard = Operation {
            owner: self.owner,
            complete: false,
        };
        self.ensure_healthy()?;
        let states = states.into_inner();
        let mut staged = *states;
        platform::dispatch(self.owner.kernel, &mut staged, blocks.into_inner())?;
        self.ensure_healthy()?;
        let completed = self
            .owner
            .completed_calls
            .get()
            .checked_add(1)
            .ok_or(Error::Invariant)?;
        *states = staged;
        self.owner.completed_calls.set(completed);
        guard.complete = true;
        Ok(())
    }
}

struct Operation<'a> {
    owner: &'a Authority,
    complete: bool,
}
impl Drop for Operation<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.owner.quarantine();
        }
    }
}

#[cfg(test)]
mod tests;
