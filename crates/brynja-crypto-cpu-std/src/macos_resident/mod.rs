//! Opt-in Apple Silicon resident/clearing profile; qualification pending.
//!
//! **Not the strict profile: no core-dump exclusion guarantee.** Locked memory
//! can still appear in dumps. This module is not exported by `brynja-strict`.
//! Applications requiring dump exclusion must not substitute it for strict APIs.
//!
//! Native macOS AArch64 only. Construction acquires guarded, locked mappings for
//! the output and a joined worker stack before accepting input. The mappings
//! are excluded from fork inheritance; deployment must still prohibit fork,
//! native thread cancellation and external protection revocation while in use.
//! Whole owned payloads, including page padding, are cleared before release;
//! worker stacks are cleared after join, including recoverable unwinding.
//! No ordinary-stack or unlocked-allocation fallback is provided.
//!
//! Caller input/copies, OS/TLS allocations, panic hooks, privileged inspection,
//! hibernation, snapshots, fatal abort and arbitrary register capture are outside
//! this guarantee. Instrumented builds are diagnostic only: interposed locking
//! and relocated stacks do not establish residency. No certification is claimed.
//! Scalar sessions never select hardware; separate features enable explicit Arm
//! routes. The separate batch feature enables explicit portable/NEON batching.
//!
//! ```no_run
//! use brynja_crypto_cpu_std::macos_resident::{Error, Limits, Sha256Session};
//! let mut session = Sha256Session::new(Limits {
//!     stack_bytes: 262144, max_stack_mapping_bytes: 1048576,
//!     max_output_mapping_bytes: 65536, max_message_bytes: 4096, max_chunks: 16,
//! })?;
//! let digest = session.hash(b"abc")?;
//! assert_eq!(digest.expose().len(), 32);
//! # Ok::<(), Error>(())
//! ```

#[cfg(feature = "macos-resident-batch")]
pub mod batch;
#[cfg(feature = "macos-resident-kmac")]
pub mod kmac;
mod resource;
pub mod sha2;
mod sha256;
pub mod sha3;
#[cfg(all(
    test,
    any(feature = "macos-resident-kmac", feature = "macos-resident-tuplehash")
))]
mod test_storage;
#[cfg(feature = "macos-resident-tuplehash")]
pub mod tuplehash;
pub use sha256::{Digest, Sha256Session};

fn require_native() -> Result<(), Error> {
    if cfg!(all(
        target_os = "macos",
        target_arch = "aarch64",
        target_endian = "little",
        target_pointer_width = "64",
        not(any(miri, kani))
    )) {
        Ok(())
    } else {
        Err(Error::Unsupported)
    }
}

/// Public resource and work bounds, checked before OS acquisition/processing.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Requested worker stack, at least 64 KiB; application must budget call depth.
    pub stack_bytes: usize,
    /// Maximum stack mapping including two guards and page rounding.
    pub max_stack_mapping_bytes: usize,
    /// Maximum output mapping including two guards and page rounding.
    pub max_output_mapping_bytes: usize,
    /// Maximum total input bytes; zero allows only empty messages.
    pub max_message_bytes: u64,
    /// Maximum chunk count, including empty chunks.
    pub max_chunks: usize,
}

/// Public failure without secret contents. No error authorizes weaker fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Not native little-endian 64-bit Apple Silicon macOS.
    Unsupported,
    /// Invalid or overflowing geometry/configuration.
    InvalidSize,
    /// Mapping reservation exceeds the caller's bound.
    ResourceLimit,
    /// Anonymous guarded mapping could not be reserved.
    Mapping,
    /// Fork-inheritance exclusion could not be acquired.
    ForkExclusion,
    /// Payload access protection could not be set.
    Access,
    /// Resident-page locking failed.
    Lock,
    /// Cleared mapping could not be released.
    Release,
    /// Native worker attributes could not be configured.
    ThreadAttributes,
    /// Native worker creation failed.
    ThreadStart,
    /// Worker panicked; join and owned-stack clearing completed.
    WorkerPanicked,
    /// Worker returned without completing the library operation.
    WorkerProtocol,
    /// Message/chunk count exceeds configured or SHA-256 domain bounds.
    WorkLimit,
    /// Internal hash/transfer invariant failed.
    Invariant,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "macOS resident profile: {self:?}")
    }
}
impl std::error::Error for Error {}
