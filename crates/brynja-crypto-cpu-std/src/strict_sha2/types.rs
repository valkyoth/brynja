use crate::protected_memory;
pub use brynja_hash_sha2::{PublicDeclassification, Sha512TBits};
use std::sync::atomic::{AtomicBool, Ordering};

/// Public algorithm identity, including the exact general SHA-512/t parameter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    /// FIPS 180-4 SHA-224.
    Sha224,
    /// FIPS 180-4 SHA-256.
    Sha256,
    /// FIPS 180-4 SHA-384.
    Sha384,
    /// FIPS 180-4 SHA-512.
    Sha512,
    /// Named SHA-512/224, distinct from general /224 metadata.
    Sha512_224,
    /// Named SHA-512/256, distinct from general /256 metadata.
    Sha512_256,
    /// General SHA-512/t for a previously validated public parameter.
    Sha512T(Sha512TBits),
}
impl Algorithm {
    /// Public output size in bits, not merely its rounded storage width.
    pub const fn output_bits(self) -> u16 {
        match self {
            Self::Sha224 | Self::Sha512_224 => 224,
            Self::Sha256 | Self::Sha512_256 => 256,
            Self::Sha384 => 384,
            Self::Sha512 => 512,
            Self::Sha512T(parameter) => parameter.bits(),
        }
    }
    /// Rounded storage width; the exact identity remains in `output_bits`.
    pub const fn output_bytes(self) -> usize {
        self.output_bits().div_ceil(8) as usize
    }
}

/// Explicit public bounds. Mapping limits account for rounding and both guards.
///
/// Two mappings are acquired: one stack and one output. Their respective limits
/// are per resource, not a process-wide quota. Use checked addition when applying
/// an aggregate application budget. Input storage remains caller-owned.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Requested worker stack reservation, at least 64 KiB.
    pub stack_bytes: usize,
    /// Bound for stack reservation including guards and page rounding.
    pub max_stack_mapping_bytes: usize,
    /// Bound for the separately mapped digest including guards and rounding.
    pub max_output_mapping_bytes: usize,
    /// Maximum total input bits in one operation; zero permits only empty input.
    pub max_message_bits: u128,
    /// Bounds iteration even for an adversarial list of empty chunks.
    pub max_chunks: usize,
}

/// Public outcome only; no hash state, message contents or private length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Required platform/storage/thread protection could not be provided.
    Resource(protected_memory::Error),
    /// Configuration cannot admit a chunk list.
    InvalidLimits,
    /// The request exceeds its public chunk or bit budget.
    WorkLimit,
    /// Total input does not fit the algorithm's encoded length domain.
    MessageTooLong,
    /// Invalid final-byte bit count or nonzero unused tail bits.
    InvalidBits,
    /// Cooperative cancellation was observed.
    Cancelled,
    /// A public declassification destination has the wrong width.
    OutputLength,
    /// An internal scoped-state or transfer invariant was violated.
    Invariant,
    /// Explicitly required compiled backend failed; never permits fallback.
    #[cfg(feature = "strict-sha2-acceleration")]
    Backend(brynja_crypto_cpu::static_execution::Error),
    /// This compiled session was irreversibly invalidated.
    #[cfg(feature = "strict-sha2-acceleration")]
    Quarantined,
}
impl From<protected_memory::Error> for Error {
    fn from(error: protected_memory::Error) -> Self {
        Self::Resource(error)
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Resource(_) => "strict SHA-2 protected resource failed",
            Self::InvalidLimits => "strict SHA-2 limits are invalid",
            Self::WorkLimit => "strict SHA-2 work limit exceeded",
            Self::MessageTooLong => "strict SHA-2 message domain exceeded",
            Self::InvalidBits => "strict SHA-2 tail is not canonical",
            Self::Cancelled => "strict SHA-2 cancelled",
            Self::OutputLength => "strict SHA-2 output length mismatch",
            Self::Invariant => "strict SHA-2 internal invariant failed",
            #[cfg(feature = "strict-sha2-acceleration")]
            Self::Backend(_) => "strict SHA-2 compiled backend failed",
            #[cfg(feature = "strict-sha2-acceleration")]
            Self::Quarantined => "strict SHA-2 compiled session quarantined",
        })
    }
}
impl std::error::Error for Error {}

/// Cooperative cancellation; cannot forcibly stop a native worker.
#[derive(Default)]
pub struct Cancellation(AtomicBool);
impl Cancellation {
    /// Creates an unset cancellation flag. It cannot be reset after cancellation.
    pub const fn new() -> Self {
        Self(AtomicBool::new(false))
    }
    /// Requests cancellation at the next bounded processing boundary.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    pub(super) fn check(&self) -> Result<(), Error> {
        if self.0.load(Ordering::Acquire) {
            Err(Error::Cancelled)
        } else {
            Ok(())
        }
    }
}
