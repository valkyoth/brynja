//! Default-off Keccak-f[1600] permutation of independent public states.
//!
//! AVX2 permutes four states; NEON permutes two and preserves slots two/three.
//! This is not the single-state SHA-3 instruction backend, ParallelHash, or
//! threading. No padding, framing, secret classification or erasure is provided.
//! Operational authority does not claim independent verification or FIPS validation.

pub use crate::static_execution::PublicData;
use core::{cell::Cell, marker::PhantomData};

#[cfg(target_arch = "aarch64")]
mod arm;
mod platform;
#[cfg(target_arch = "x86_64")]
mod x86;

/// Independent-state vector identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kernel {
    /// Four independent states; AVX2 and OS-enabled YMM state required.
    Avx2,
    /// Two independent states; AArch64 NEON required, not SHA-3 instructions.
    Neon,
}

impl Kernel {
    /// Number of active independent states.
    pub const fn width(self) -> usize {
        match self {
            Self::Avx2 => 4,
            Self::Neon => 2,
        }
    }
    fn architecture(self) -> bool {
        match self {
            Self::Avx2 => cfg!(target_arch = "x86_64"),
            Self::Neon => cfg!(target_arch = "aarch64"),
        }
    }
    /// Compile-time bundle, not a runtime CPU probe.
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

/// No error authorizes fallback to a different backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Requested kernel belongs to another architecture.
    WrongArchitecture,
    /// Compiled feature bundle is incomplete.
    MissingFeatures,
    /// Startup KAT, revalidation or operation invalidated this owner.
    Quarantined,
    /// Fixed-size or accounting invariant failed.
    Invariant,
}

/// Thread-bound, non-cloneable authority with permanent owner-local quarantine.
/// Quarantine on panic requires unwinding; `panic = "abort"` does not run Drop.
/// Neither a startup KAT nor cached detection proves CPU migration safety.
///
/// ```compile_fail
/// use brynja_crypto_cpu::keccak_batch::Authority;
/// fn send<T: Send>() {} send::<Authority>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu::keccak_batch::Authority;
/// fn sync<T: Sync>() {} sync::<Authority>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu::keccak_batch::Authority;
/// fn clone<T: Clone>() {} clone::<Authority>();
/// ```
pub struct Authority {
    kernel: Kernel,
    healthy: Cell<bool>,
    completed_calls: Cell<u64>,
    revalidate: fn(Kernel) -> bool,
    thread_bound: PhantomData<*mut ()>,
}

impl Authority {
    /// Runs the actual vector KAT under the executable's target-feature contract.
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
        let mut states = core::hint::black_box([[0; 25]; 4]);
        owner.session()?.permute(PublicData::new(&mut states))?;
        if !states
            .iter()
            .take(kernel.width())
            .all(|s| *s == crate::keccak_constants::ZERO_STATE_RESULT)
            || !states.iter().skip(kernel.width()).all(|s| *s == [0; 25])
        {
            owner.quarantine();
            return Err(Error::Quarantined);
        }
        owner.completed_calls.set(0);
        Ok(owner)
    }
    /// Permanently revokes this authority and all its sessions.
    pub fn quarantine(&self) {
        self.healthy.set(false);
    }
    /// Diagnostic health, not an authorization capability.
    pub fn is_healthy(&self) -> bool {
        self.healthy.get()
    }
    /// Borrows authority; sessions cannot outlive their owner.
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

/// Borrowed, non-cloneable permutation capability. Public states only.
///
/// ```compile_fail
/// use brynja_crypto_cpu::keccak_batch::Session;
/// fn send<T: Send>() {} send::<Session<'static>>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu::keccak_batch::Session;
/// fn clone<T: Clone>() {} clone::<Session<'static>>();
/// ```
pub struct Session<'a> {
    owner: &'a Authority,
}

impl Session<'_> {
    /// Exact vector identity, including active width.
    pub const fn kernel(&self) -> Kernel {
        self.owner.kernel
    }
    /// Successful vector calls, excluding startup KAT. Not a permission token.
    pub fn completed_vector_calls(&self) -> u64 {
        self.owner.completed_calls.get()
    }
    /// Revalidates health; cached detection is not a live migration monitor.
    pub fn ensure_healthy(&self) -> Result<(), Error> {
        self.owner.check()
    }
    /// Permanently revokes all sessions borrowed from the same owner.
    pub fn quarantine(&self) {
        self.owner.quarantine();
    }
    /// Permutes every active state, preserving all caller states on error.
    /// PublicData is caller-asserted provenance, not runtime verification or
    /// declassification. Never supply secrets; neither state nor staging erases.
    pub fn permute(&self, states: PublicData<&mut [[u64; 25]; 4]>) -> Result<(), Error> {
        let mut guard = Operation {
            owner: self.owner,
            complete: false,
        };
        self.ensure_healthy()?;
        let completed = self
            .owner
            .completed_calls
            .get()
            .checked_add(1)
            .ok_or(Error::Invariant)?;
        let states = states.into_inner();
        let mut staged = *states;
        platform::dispatch(self.kernel(), &mut staged)?;
        self.ensure_healthy()?;
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
