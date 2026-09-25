use brynja_crypto_cpu_std::protected_memory;
pub use brynja_legacy_md5::PublicDeclassification;
use std::sync::atomic::{AtomicBool, Ordering};

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
    /// Total input overflows checked u128 accounting, not MD5's low-64-bit encoding.
    MessageTooLong,
    /// Invalid final-byte bit count or nonzero unused tail bits.
    InvalidBits,
    /// Cooperative cancellation was observed.
    Cancelled,
    /// A public declassification destination has the wrong width.
    OutputLength,
    /// An internal scoped-state or transfer invariant was violated.
    Invariant,
}
impl From<protected_memory::Error> for Error {
    fn from(error: protected_memory::Error) -> Self {
        Self::Resource(error)
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Resource(_) => "strict legacy MD5 protected resource failed",
            Self::InvalidLimits => "strict legacy MD5 limits are invalid",
            Self::WorkLimit => "strict legacy MD5 work limit exceeded",
            Self::MessageTooLong => "strict legacy MD5 length accounting overflow",
            Self::InvalidBits => "strict legacy MD5 tail is not canonical",
            Self::Cancelled => "strict legacy MD5 cancelled",
            Self::OutputLength => "strict legacy MD5 output length mismatch",
            Self::Invariant => "strict legacy MD5 internal invariant failed",
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
