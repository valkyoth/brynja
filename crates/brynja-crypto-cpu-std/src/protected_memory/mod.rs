//! Opt-in, bounded, resident and core-dump-excluded byte storage.
//! This resource is NOT strict execution admission. In particular, borrowing
//! these bytes does not protect the caller's stack, registers or other copies.
//! [`ProtectedStack`] separately provides joined single/group protected-stack execution.
//! Separate default-off strict session features integrate these resources with
//! cryptography; this generic byte/stack API alone does not admit such execution.
//!
//! The initial adapter supports Linux GNU on x86-64 and little-endian AArch64.
//! It requires Linux 4.4/glibc 2.27 or newer for eager `mlock2` (zero flags).
//! There is no fallback to the older `mlock` symbol, which sanitizers may no-op.
//! Instrumented diagnostic builds must not process real secrets; ASan fake-stack
//! relocation is incompatible with the protected-stack placement guarantee.
//! Other targets and verification-model builds return [`Error::Unsupported`].
//! Construction acquires OS protections before exposing zero-initialized bytes;
//! it never falls back to an ordinary allocation. The whole resident mapping,
//! including page-rounding padding, is cleared before unmapping releases locks.
//!
//! The deployment must not revoke protections (e.g. `munlockall`, `madvise`,
//! `mprotect`), fork while these resources are live, or access them through raw
//! pointers. Regions are excluded from fork inheritance. This is not protection
//! against privileged inspection, hibernation or hypervisor snapshots. Forgetting
//! the owner leaks its locked mapping; forgetting a borrowed view does not.

#[cfg(all(
    target_os = "linux",
    target_env = "gnu",
    target_pointer_width = "64",
    not(any(miri, kani)),
    any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_endian = "little")
    )
))]
mod platform;
#[cfg(not(all(
    target_os = "linux",
    target_env = "gnu",
    target_pointer_width = "64",
    not(any(miri, kani)),
    any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_endian = "little")
    )
)))]
mod unsupported;
#[cfg(not(all(
    target_os = "linux",
    target_env = "gnu",
    target_pointer_width = "64",
    not(any(miri, kani)),
    any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_endian = "little")
    )
)))]
use unsupported as platform;

#[cfg(test)]
mod tests;

// Native resource tests share the process's finite RLIMIT_MEMLOCK. Serialize
// test cases, not their workers, so --all-features/high-core hosts do not turn
// legitimate residency exhaustion into unrelated family-test failures.
#[cfg(test)]
pub(crate) fn test_resource_guard() -> std::sync::MutexGuard<'static, ()> {
    static TEST_RESOURCES: std::sync::Mutex<()> = std::sync::Mutex::new(());
    match TEST_RESOURCES.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Public resource failures, never containing secret bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// No implemented adapter for this OS, ABI, architecture or model build.
    Unsupported,
    /// Empty request, invalid page geometry, or checked size overflow.
    InvalidSize,
    /// Requested size, including guards and rounding, exceeds the supplied bound.
    ResourceLimit,
    /// The OS could not reserve an anonymous mapping.
    Mapping,
    /// Resident-page locking failed; no bytes were exposed.
    Lock,
    /// Core-dump exclusion failed; no bytes were exposed.
    DumpExclusion,
    /// Fork inheritance exclusion failed; no bytes were exposed.
    ForkExclusion,
    /// The OS could not enable access to the guarded payload.
    Access,
    /// Unmapping failed. Explicit close retains the cleared owner for retry.
    Release,
    /// Native thread attributes could not be initialized/configured.
    ThreadAttributes,
    /// A native worker could not start. There is no ordinary-stack fallback.
    ThreadStart,
    /// The callback panicked and unwound on its worker; its stack was cleared.
    WorkerPanicked,
    /// The worker terminated without completing the Rust callback protocol.
    WorkerProtocol,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Unsupported => "protected storage is unsupported on this target",
            Self::InvalidSize => "invalid protected storage geometry",
            Self::ResourceLimit => "protected storage resource limit exceeded",
            Self::Mapping => "protected storage mapping failed",
            Self::Lock => "protected storage residency lock failed",
            Self::DumpExclusion => "protected storage dump exclusion failed",
            Self::ForkExclusion => "protected storage fork exclusion failed",
            Self::Access => "protected storage payload access failed",
            Self::Release => "cleared protected storage could not be released",
            Self::ThreadAttributes => "protected worker attributes failed",
            Self::ThreadStart => "protected worker could not start",
            Self::WorkerPanicked => "protected worker callback panicked",
            Self::WorkerProtocol => "protected worker did not complete its callback",
        })
    }
}

impl std::error::Error for Error {}

/// Fixed-size protected bytes, without implicit formatting, copying or sharing.
///
/// There is no resize, raw ownership export, deref coercion or implicit public
/// digest conversion. Borrowed access is explicit and retains this owner.
///
/// ```compile_fail
/// use brynja_crypto_cpu_std::protected_memory::ProtectedBytes;
/// fn require<T: Send>() {}
/// require::<ProtectedBytes>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu_std::protected_memory::ProtectedBytes;
/// fn require<T: Sync>() {}
/// require::<ProtectedBytes>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu_std::protected_memory::ProtectedBytes;
/// fn require<T: Clone>() {}
/// require::<ProtectedBytes>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu_std::protected_memory::ProtectedBytes;
/// fn require<T: Copy>() {}
/// require::<ProtectedBytes>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu_std::protected_memory::ProtectedBytes;
/// fn require<T: core::fmt::Debug>() {}
/// require::<ProtectedBytes>();
/// ```
pub struct ProtectedBytes {
    mapping: platform::Mapping,
    // No manual Send/Sync. Future workers require a distinct scoped loan design.
    _local: core::marker::PhantomData<std::rc::Rc<()>>,
}

impl ProtectedBytes {
    /// Acquires zeroed storage with two inaccessible guard pages.
    ///
    /// `max_mapping_bytes` bounds the entire mapping, including guard pages and
    /// payload rounding. OS residency limits are an additional bound. The bound
    /// is per resource, not a process-wide allocation budget.
    pub fn new(bytes: usize, max_mapping_bytes: usize) -> Result<Self, Error> {
        Ok(Self {
            mapping: platform::Mapping::new(bytes, max_mapping_bytes)?,
            _local: core::marker::PhantomData,
        })
    }

    /// Borrows protected storage; does not declassify it or protect the borrower.
    pub fn as_bytes(&self) -> &[u8] {
        self.mapping.bytes()
    }

    /// Exclusively borrows protected storage without copying or resizing it.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        self.mapping.bytes_mut()
    }

    /// Clears the complete payload including alignment padding, retaining locks.
    pub fn clear(&mut self) {
        self.mapping.clear();
    }

    /// Clears and releases storage. On OS failure the cleared owner is retained.
    ///
    /// Drop also clears and attempts release. If the OS refuses unmapping even
    /// on Drop, cleared storage is leaked rather than exposing uncleared pages.
    pub fn close(mut self) -> Result<(), (Error, Self)> {
        match self.mapping.close() {
            Ok(()) => Ok(()),
            Err(error) => Err((error, self)),
        }
    }
}

mod stack;
pub use stack::ProtectedStack;

#[cfg(any(
    test,
    all(
        target_os = "linux",
        target_env = "gnu",
        target_pointer_width = "64",
        not(any(miri, kani)),
        any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        )
    )
))]
mod geometry {
    use super::Error;
    // Geometry contains public sizes only. Every addition precedes OS allocation.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) struct Layout {
        pub(super) payload: usize,
        pub(super) total: usize,
        pub(super) page: usize,
    }

    impl Layout {
        pub(super) fn new(bytes: usize, max: usize, page: usize) -> Result<Self, Error> {
            if bytes == 0 || !page.is_power_of_two() {
                return Err(Error::InvalidSize);
            }
            let rounded = bytes
                .checked_next_multiple_of(page)
                .ok_or(Error::InvalidSize)?;
            let total = page
                .checked_mul(2)
                .and_then(|guards| rounded.checked_add(guards))
                .filter(|size| *size <= isize::MAX as usize)
                .ok_or(Error::InvalidSize)?;
            if total > max {
                return Err(Error::ResourceLimit);
            }
            Ok(Self {
                payload: rounded,
                total,
                page,
            })
        }
    }
}
