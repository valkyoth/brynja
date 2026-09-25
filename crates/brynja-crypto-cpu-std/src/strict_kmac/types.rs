use crate::protected_memory;
pub use brynja_mac_kmac::KmacPublicDeclassification as PublicDeclassification;
use std::sync::atomic::{AtomicBool, Ordering};

/// Exact public construction and output-bit width; fixed and XOF are distinct.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    /// Fixed KMAC128, requiring at least 128 output bits.
    Kmac128(usize),
    /// Fixed KMAC256, requiring at least 256 output bits.
    Kmac256(usize),
    /// KMACXOF128, including empty derived output (not an authenticator).
    KmacXof128(usize),
    /// KMACXOF256, including empty derived output (not an authenticator).
    KmacXof256(usize),
}
impl Algorithm {
    /// Exact output-bit count, retained even for equal rounded widths.
    pub const fn output_bits(self) -> usize {
        match self {
            Self::Kmac128(n) | Self::Kmac256(n) | Self::KmacXof128(n) | Self::KmacXof256(n) => n,
        }
    }
    /// Canonical output storage width; unused high bits are zero.
    pub const fn output_bytes(self) -> usize {
        self.output_bits().div_ceil(8)
    }
    pub(super) const fn strength(self) -> usize {
        match self {
            Self::Kmac128(_) | Self::KmacXof128(_) => 128,
            _ => 256,
        }
    }
    pub(super) const fn xof(self) -> bool {
        matches!(self, Self::KmacXof128(_) | Self::KmacXof256(_))
    }
}

/// Raw borrowed LSB-first bits; contents are validated only on the protected worker.
pub struct Bits<'a> {
    /// Original caller storage remains the caller's protection responsibility.
    pub bytes: &'a [u8],
    /// Zero for empty; otherwise 1..=8, with unused high bits zero.
    pub valid_bits: u8,
}
impl<'a> Bits<'a> {
    /// Empty canonical input.
    pub const fn empty() -> Self {
        Self {
            bytes: &[],
            valid_bits: 0,
        }
    }
    /// Borrow bytes without inspecting their contents.
    pub const fn bytes(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            valid_bits: if bytes.is_empty() { 0 } else { 8 },
        }
    }
}

/// Borrowed complete request. Key/customization are not retained between calls.
pub struct Request<'a> {
    /// Full-strength key (at least 128 or 256 bits); no conformance bypass.
    pub key: Bits<'a>,
    /// Arbitrary-bit SP 800-185 customization.
    pub customization: Bits<'a>,
    /// Byte-aligned message chunks, including permitted empty chunks.
    pub chunks: &'a [&'a [u8]],
    /// Final canonical message bits, following all chunks.
    pub tail: Bits<'a>,
}

/// Three independent mapping budgets, not a process-wide quota.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Worker stack reservation (at least 64 KiB).
    pub stack_bytes: usize,
    /// Stack budget including guards and rounding.
    pub max_stack_mapping_bytes: usize,
    /// Each of output and staging has this separate mapping budget.
    pub max_buffer_mapping_bytes: usize,
    /// Message budget, excluding key and customization.
    pub max_message_bits: u128,
    /// Combined key/customization budget; setup is not internally cancellable.
    pub max_setup_bits: usize,
    /// Exact output-bit work limit.
    pub max_output_bits: usize,
    /// Maximum chunk count, even if all are empty; must be nonzero.
    pub max_chunks: usize,
}

/// Public error categories; no private state or key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Required OS/target/thread protection failed.
    Resource(protected_memory::Error),
    /// Invalid session configuration.
    InvalidLimits,
    /// Public work budget exceeded.
    WorkLimit,
    /// Checked length arithmetic failed.
    MessageTooLong,
    /// Noncanonical bit shape or content.
    InvalidBits,
    /// Key shorter than the selected construction's strength.
    KeyTooShort,
    /// Fixed generation or verification below the selected strength.
    TagTooShort,
    /// Explicit output/candidate bit width does not match this session.
    OutputLength,
    /// Cooperative cancellation observed.
    Cancelled,
    /// Scoped computation or transfer failed an invariant.
    Invariant,
    /// Required compiled backend failed; never authorizes fallback.
    #[cfg(feature = "strict-kmac-acceleration")]
    Backend(brynja_crypto_cpu::static_execution::Error),
    /// Scoped accelerated KMAC failed; the wrapper is terminal, with no fallback.
    #[cfg(feature = "strict-kmac-acceleration")]
    Execution(brynja_mac_kmac::KmacError),
    /// The compiled wrapper was irreversibly invalidated.
    #[cfg(feature = "strict-kmac-acceleration")]
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
            Self::Resource(_) => "strict KMAC protected resource failed",
            Self::InvalidLimits => "strict KMAC invalid limits",
            Self::WorkLimit => "strict KMAC work limit exceeded",
            Self::MessageTooLong => "strict KMAC length domain exceeded",
            Self::InvalidBits => "strict KMAC noncanonical bits",
            Self::KeyTooShort => "strict KMAC key too short",
            Self::TagTooShort => "strict KMAC tag too short",
            Self::OutputLength => "strict KMAC output width mismatch",
            Self::Cancelled => "strict KMAC cancelled",
            Self::Invariant => "strict KMAC invariant failed",
            #[cfg(feature = "strict-kmac-acceleration")]
            Self::Backend(_) => "strict KMAC compiled backend failed",
            #[cfg(feature = "strict-kmac-acceleration")]
            Self::Execution(_) => "strict KMAC accelerated computation failed",
            #[cfg(feature = "strict-kmac-acceleration")]
            Self::Quarantined => "strict KMAC compiled session quarantined",
        })
    }
}
impl std::error::Error for Error {}

/// One-way cooperative cancellation, never native-thread cancellation.
#[derive(Default)]
pub struct Cancellation(AtomicBool);
impl Cancellation {
    /// Unset cancellation flag.
    pub const fn new() -> Self {
        Self(AtomicBool::new(false))
    }
    /// Requests cancellation at the next library checkpoint.
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
