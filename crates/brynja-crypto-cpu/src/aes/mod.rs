//! Explicit AES expansion and round execution for specialized `no_std` builds.
//!
//! Cargo enables an API, not an ISA. The compiler must enable the full bundle;
//! deployment must keep that bundle available on every eligible CPU, including
//! across migration. There is no runtime detection or fallback in this module.
//! The separate runtime feature permits an unsafe platform integration boundary;
//! ordinary hosted callers should use `brynja_crypto_cpu_std::aes`.
//! Low-level callers own and clear their input, forward schedule and output.
//! Prefer the clearing key owners in `brynja_crypto::aes::execution`.
//! Arm DIT scopes cover raw kernels, not the surrounding owner operations.
//! The x86 path does not configure a comparable processor timing mode; AES-NI
//! selection is not a whole-wrapper timing or physical-side-channel guarantee.
//! In particular, it does not detect or configure Intel DOITM. Deployments
//! relying on Intel's DOIT guarantees must establish the applicable CPU,
//! microcode and OS-managed mode on every eligible logical processor.
//! Arm DIT availability alone does not establish data-prefetcher mitigation
//! (notably on Apple M1/M2), including for work outside the raw kernel scopes.
//! Development scope: native/platform and emitted-code qualification is pending.

use core::{cell::Cell, marker::PhantomData};

#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
mod aarch64;
#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
mod aarch64_expand;
mod dit;
mod kat;
pub use dit::DitPolicy;
#[cfg(target_arch = "x86_64")]
mod x86;
#[cfg(target_arch = "x86_64")]
mod x86_expand;

/// Exact single-block AES instruction bundle, independent of key width.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Kernel {
    /// x86_64 AES-NI and SSE2; no AVX or VAES instruction is used.
    X86AesNi,
    /// Little-endian AArch64 NEON and AES.
    ArmAes,
}

impl Kernel {
    fn check_architecture(self) -> Result<(), Error> {
        match self {
            Self::X86AesNi if cfg!(target_arch = "x86_64") => Ok(()),
            Self::ArmAes if cfg!(all(target_arch = "aarch64", target_endian = "little")) => Ok(()),
            _ => Err(Error::WrongArchitecture),
        }
    }
    /// Checks compiled architecture and features, not the current host CPU.
    pub const fn check_compiled_target(self) -> Result<(), Error> {
        let (architecture, bundle) = match self {
            Self::X86AesNi => (
                cfg!(target_arch = "x86_64"),
                cfg!(all(target_feature = "aes", target_feature = "sse2")),
            ),
            Self::ArmAes => (
                cfg!(all(target_arch = "aarch64", target_endian = "little")),
                cfg!(all(target_feature = "aes", target_feature = "neon")),
            ),
        };
        if !architecture {
            return Err(Error::WrongArchitecture);
        }
        if !bundle {
            return Err(Error::MissingTargetFeatures);
        }
        Ok(())
    }
}

/// Closed, value-free execution errors; none authorizes fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// The selected architecture or byte order does not match this build.
    WrongArchitecture,
    /// The compiler's complete target-feature bundle is absent.
    MissingTargetFeatures,
    /// Requested Arm DIT is unavailable, or enabling it failed before secret work.
    DitUnavailable,
    /// Startup testing is not complete.
    NotReady,
    /// This owner is permanently quarantined.
    Quarantined,
    /// The borrowed permit no longer matches the owner generation.
    StaleGeneration,
    /// An internal fixed-domain invariant failed.
    InternalDomain,
}

/// Owner-local health, not a physical-fault or certification assertion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Health {
    /// Direct startup known-answer testing is in progress.
    Testing,
    /// All three expansion schedules and six width/direction known answers passed.
    Healthy,
    /// Irreversibly revoked; no reset or retry exists on this owner.
    Quarantined,
}

/// Copyable observation only; cannot create an execution permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Report {
    /// Exact instruction bundle.
    pub kernel: Kernel,
    /// Current owner health.
    pub health: Health,
    /// Owner-local lifecycle epoch (testing, admitted, terminal), not a
    /// process-global identity or operation counter. Authorities cannot reset.
    pub generation: u64,
}

/// Sealed, thread-bound static or platform execution authority. No Clone or reset.
/// Startup failure returns a quarantined owner so the failure is observable.
///
/// ```compile_fail
/// fn send<T: Send>() {}
/// send::<brynja_crypto_cpu::aes::Authority>();
/// ```
/// ```compile_fail
/// fn cloneable<T: Clone>() {}
/// cloneable::<brynja_crypto_cpu::aes::Authority>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu::aes::{Authority, Report};
/// fn forge(report: Report) -> Authority { report.into() }
/// ```
pub struct Authority {
    kernel: Kernel,
    admission: Admission,
    dit: bool,
    health: Cell<Health>,
    generation: Cell<u64>,
    local: PhantomData<*mut ()>,
}

// Not constructible from feature masks or reports by safe downstream code.
enum Admission {
    Static,
    #[cfg(feature = "aes-runtime-execution")]
    Platform,
}

impl Authority {
    /// Checks the exact static ISA, then tests expansion and both block directions
    /// for every key width against independent fixed known answers.
    /// No kernel instruction is entered for missing features or wrong targets.
    /// Static target specialization is a deployment requirement, not detection.
    /// Uses `DitPolicy::IfAvailable`: Arm DIT is admitted only when this build
    /// enables `+dit`. Use `new_with_dit` with `Require` to reject its absence.
    pub fn new(kernel: Kernel) -> Result<Self, Error> {
        Self::new_with_dit(kernel, DitPolicy::IfAvailable)
    }

    /// Static admission with an explicit DIT policy. `Require` rejects non-Arm
    /// targets and builds without `+dit`; it never substitutes portable AES.
    /// A specialized build must run only where its complete ISA is supported.
    pub fn new_with_dit(kernel: Kernel, policy: DitPolicy) -> Result<Self, Error> {
        kernel.check_compiled_target()?;
        let enabled = dit::admit(
            policy,
            kernel == Kernel::ArmAes && cfg!(target_feature = "dit"),
        )?;
        Ok(Self::start_with_dit(kernel, Admission::Static, enabled))
    }

    /// Creates an owner under a platform's lifetime-long instruction guarantee.
    /// Startup failure yields a quarantined owner, never a portable replacement.
    /// Prefer the safe, separately packaged hosted adapter.
    ///
    /// # Safety
    /// Every CPU eligible to run this thread must support the complete Rust ISA
    /// bundle (x86 AES/SSE2 or little-endian Arm AES/NEON) and required OS register
    /// state for this owner's entire lifetime, including hotplug and VM migration.
    /// Current-core CPUID, thread affinity observation, a KAT or a thread-bound
    /// owner alone cannot establish this guarantee. No reentrant signal use.
    ///
    /// ```compile_fail
    /// use brynja_crypto_cpu::aes::{Authority, Kernel};
    /// let owner = Authority::from_platform(Kernel::X86AesNi);
    /// ```
    #[cfg(feature = "aes-runtime-execution")]
    #[allow(unsafe_code)]
    pub unsafe fn from_platform(kernel: Kernel) -> Result<Self, Error> {
        kernel.check_architecture()?;
        Ok(Self::start_with_dit(kernel, Admission::Platform, false))
    }

    /// Platform admission including optional DIT capability. The safe hosted
    /// adapter performs detection; this unsafe boundary is for platform authors.
    ///
    /// # Safety
    /// All obligations of `from_platform` apply. If `dit_available` is true,
    /// every eligible CPU must additionally support FEAT_DIT, EL0 DIT access,
    /// and OS preservation of PSTATE.DIT for this owner's lifetime. No signal
    /// handler may change DIT and resume this operation with a different state.
    ///
    /// ```compile_fail
    /// use brynja_crypto_cpu::aes::{Authority, DitPolicy, Kernel};
    /// let owner = Authority::from_platform_with_dit(Kernel::ArmAes, DitPolicy::Require, true);
    /// ```
    #[cfg(feature = "aes-runtime-execution")]
    #[allow(unsafe_code)]
    pub unsafe fn from_platform_with_dit(
        kernel: Kernel,
        policy: DitPolicy,
        dit_available: bool,
    ) -> Result<Self, Error> {
        kernel.check_architecture()?;
        let enabled = dit::admit(policy, kernel == Kernel::ArmAes && dit_available)?;
        Ok(Self::start_with_dit(kernel, Admission::Platform, enabled))
    }

    /// Whether each expansion/block kernel is scoped with DIT enabled. This is
    /// not the caller's current PSTATE value or a whole-application timing claim.
    pub fn dit_enabled(&self) -> bool {
        self.dit
    }

    fn start_with_dit(kernel: Kernel, admission: Admission, dit: bool) -> Self {
        let owner = Self {
            kernel,
            admission,
            dit,
            health: Cell::new(Health::Testing),
            generation: Cell::new(1),
            local: PhantomData,
        };
        let passed = kat::known_answers(&owner);
        owner.complete_startup(passed);
        owner
    }

    fn complete_startup(&self, passed: bool) {
        self.generation.set(2);
        self.health.set(if passed {
            Health::Healthy
        } else {
            Health::Quarantined
        });
    }

    /// Returns a non-authorizing health observation.
    pub fn report(&self) -> Report {
        Report {
            kernel: self.kernel,
            health: self.health.get(),
            generation: self.generation.get(),
        }
    }

    /// Borrows a permit bound to this owner's lifetime and generation.
    pub fn session(&self) -> Result<Session<'_>, Error> {
        self.check(self.generation.get())?;
        Ok(Session {
            owner: self,
            generation: self.generation.get(),
        })
    }

    /// Permanently invalidates this owner and every outstanding permit.
    /// Idempotent; no counters wrap, recovery, or automatic retry is provided.
    pub fn quarantine(&self) {
        if self.health.get() != Health::Quarantined {
            self.health.set(Health::Quarantined);
            self.generation.set(3);
        }
    }

    fn check(&self, generation: u64) -> Result<(), Error> {
        match self.health.get() {
            Health::Testing => return Err(Error::NotReady),
            Health::Quarantined => return Err(Error::Quarantined),
            Health::Healthy => {}
        }
        if generation != self.generation.get() {
            return Err(Error::StaleGeneration);
        }
        self.check_admission()
    }

    fn check_admission(&self) -> Result<(), Error> {
        self.kernel.check_architecture()?;
        match self.admission {
            Admission::Static => self.kernel.check_compiled_target(),
            #[cfg(feature = "aes-runtime-execution")]
            Admission::Platform => Ok(()),
        }
    }
}

/// Borrowed non-cloneable permit. Raw state and schedules remain caller-owned.
/// These synchronous calls do not allocate or invoke callbacks. A copied report
/// cannot renew a permit; quarantine applies to all permits from this owner.
///
/// # Secret handling
/// This is an opt-in low-level interface, not a clearing key owner. Forward
/// schedules are key-equivalent material; caller buffers are not cleared on
/// success, error, quarantine or drop. Prefer `brynja_crypto::aes::execution`
/// unless the integration explicitly owns their complete clearing lifecycle.
pub struct Session<'a> {
    owner: &'a Authority,
    generation: u64,
}

macro_rules! operations {
    ($expand:ident, $encrypt:ident, $decrypt:ident, $key_bytes:literal, $bytes:literal, $keys:literal) => {
        /// Expands a key into its complete forward round schedule.
        /// Admission rejection before entry preserves the output. Caller owns
        /// and clears both buffers, including any output after a later error.
        pub fn $expand(
            &self,
            key: &[u8; $key_bytes],
            schedule: &mut [u8; $bytes],
        ) -> Result<(), Error> {
            self.expand(key, schedule)
        }
        /// Encrypts one block using the caller's forward round schedule.
        /// Errors before entry preserve state; neither caller buffer is cleared.
        pub fn $encrypt(&self, state: &mut [u8; 16], schedule: &[u8; $bytes]) -> Result<(), Error> {
            self.transform::<$bytes, $keys>(state, schedule, false)
        }
        /// Decrypts one block using the same forward round schedule.
        /// Errors before entry preserve state; plaintext remains caller-owned.
        pub fn $decrypt(&self, state: &mut [u8; 16], schedule: &[u8; $bytes]) -> Result<(), Error> {
            self.transform::<$bytes, $keys>(state, schedule, true)
        }
    };
}

impl Session<'_> {
    /// Rechecks generation, health and sealed static/platform admission before
    /// secret work. Platform availability is a constructor lifetime obligation,
    /// not a fresh per-call CPU probe.
    pub fn check(&self) -> Result<(), Error> {
        self.owner.check(self.generation)
    }
    /// Current owner health observation only.
    pub fn report(&self) -> Report {
        self.owner.report()
    }
    /// Permanently invalidates the owner after a consumer's failed operation.
    pub fn quarantine(&self) {
        self.owner.quarantine();
    }

    operations!(expand128, encrypt128, decrypt128, 16, 176, 11);
    operations!(expand192, encrypt192, decrypt192, 24, 208, 13);
    operations!(expand256, encrypt256, decrypt256, 32, 240, 15);

    fn expand<const K: usize, const S: usize>(
        &self,
        key: &[u8; K],
        schedule: &mut [u8; S],
    ) -> Result<(), Error> {
        self.check()?;
        let guard = Operation {
            session: self,
            completed: false,
        };
        dispatch_expansion(self.owner, key, schedule)?;
        guard.complete()
    }

    fn transform<const S: usize, const N: usize>(
        &self,
        state: &mut [u8; 16],
        schedule: &[u8; S],
        inverse: bool,
    ) -> Result<(), Error> {
        self.check()?;
        let guard = Operation {
            session: self,
            completed: false,
        };
        let keys = schedule
            .as_chunks::<16>()
            .0
            .try_into()
            .map_err(|_| Error::InternalDomain)?;
        dispatch::<N>(self.owner, state, keys, inverse)?;
        guard.complete()
    }
}

struct Operation<'a, 'owner> {
    session: &'a Session<'owner>,
    completed: bool,
}
impl Operation<'_, '_> {
    fn complete(mut self) -> Result<(), Error> {
        // Expansion and transforms share the same post-execution invariant.
        // A failed recheck leaves Drop responsible for terminal quarantine.
        self.session.check()?;
        self.completed = true;
        Ok(())
    }
}
impl Drop for Operation<'_, '_> {
    fn drop(&mut self) {
        if !self.completed {
            self.session.quarantine();
        }
    }
}

#[allow(unsafe_code)]
fn dispatch<const N: usize>(
    owner: &Authority,
    state: &mut [u8; 16],
    schedule: &[[u8; 16]; N],
    inverse: bool,
) -> Result<(), Error> {
    owner.check_admission()?;
    let kernel = owner.kernel;
    #[cfg(target_arch = "x86_64")]
    if kernel == Kernel::X86AesNi {
        // SAFETY: Either the exact static bundle was checked, or this sealed
        // owner was created under from_platform's lifetime-long CPU/OS contract.
        // Typed, disjoint state/schedule borrows bound every access.
        unsafe { x86::transform(state, schedule, inverse) };
        return Ok(());
    }
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    if kernel == Kernel::ArmAes {
        // SAFETY: DIT capability is sealed at static/platform admission.
        let _dit = unsafe { dit::enter(owner.dit) }?;
        // SAFETY: Exact little-endian NEON/AES static/platform admission above, with the
        // same deployment and typed memory preconditions as the x86 route.
        unsafe { aarch64::transform(state, schedule, inverse) };
        return Ok(());
    }
    let _ = (kernel, state, schedule, inverse);
    Err(Error::WrongArchitecture)
}

#[cfg(test)]
mod tests;

#[allow(unsafe_code)]
fn dispatch_expansion<const K: usize, const S: usize>(
    owner: &Authority,
    key: &[u8; K],
    schedule: &mut [u8; S],
) -> Result<(), Error> {
    const { assert!(matches!((K, S), (16, 176) | (24, 208) | (32, 240))) };
    owner.check_admission()?;
    let kernel = owner.kernel;
    #[cfg(target_arch = "x86_64")]
    if kernel == Kernel::X86AesNi {
        // SAFETY: Sealed static/platform admission above guarantees AES/SSE2
        // for this call's lifetime. Typed disjoint arrays have exact dimensions.
        unsafe { x86_expand::expand(key, schedule) };
        return Ok(());
    }
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    if kernel == Kernel::ArmAes {
        // SAFETY: Same lifetime-long DIT admission as the block dispatcher.
        let _dit = unsafe { dit::enter(owner.dit) }?;
        // SAFETY: Sealed little-endian NEON/AES lifetime guarantee above.
        // Typed disjoint ordinary-memory arrays bound all unaligned accesses.
        unsafe { aarch64_expand::expand(key, schedule) };
        return Ok(());
    }
    let _ = (kernel, key, schedule);
    Err(Error::WrongArchitecture)
}
