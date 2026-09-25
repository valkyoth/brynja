use crate::protected_memory;
pub use brynja_hash_sha3::Sha3PublicDeclassification as PublicDeclassification;
use std::sync::atomic::{AtomicBool, Ordering};

/// Public identity and exact requested output size. No implicit XOF default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    /// FIPS 202 SHA3-224.
    Sha3_224,
    /// FIPS 202 SHA3-256.
    Sha3_256,
    /// FIPS 202 SHA3-384.
    Sha3_384,
    /// FIPS 202 SHA3-512.
    Sha3_512,
    /// FIPS 202 SHAKE128 with an exact bit count, including zero.
    Shake128(usize),
    /// FIPS 202 SHAKE256 with an exact bit count, including zero.
    Shake256(usize),
    /// SP 800-185 cSHAKE128; N/S are supplied with each request.
    Cshake128(usize),
    /// SP 800-185 cSHAKE256; N/S are supplied with each request.
    Cshake256(usize),
}
impl Algorithm {
    /// Exact public output width, not just its rounded storage width.
    pub const fn output_bits(self) -> usize {
        match self {
            Self::Sha3_224 => 224,
            Self::Sha3_256 => 256,
            Self::Sha3_384 => 384,
            Self::Sha3_512 => 512,
            Self::Shake128(n) | Self::Shake256(n) | Self::Cshake128(n) | Self::Cshake256(n) => n,
        }
    }
    /// Required canonical storage width. Partial bytes use low-order bits.
    pub const fn output_bytes(self) -> usize {
        self.output_bits().div_ceil(8)
    }
    pub(super) const fn customized(self) -> bool {
        matches!(self, Self::Cshake128(_) | Self::Cshake256(_))
    }
}

/// Borrowed raw LSB-first bit string. No secret bytes are copied or formatted.
/// Canonicality is checked only after entering the protected worker.
pub struct Bits<'a> {
    /// Caller-owned bytes, outside this wrapper's storage guarantee.
    pub bytes: &'a [u8],
    /// Zero for empty input; otherwise 1..=8 with unused high bits zero.
    pub valid_bits: u8,
}
impl<'a> Bits<'a> {
    /// An empty string without a fractional byte.
    pub const fn empty() -> Self {
        Self {
            bytes: &[],
            valid_bits: 0,
        }
    }
    /// A borrowed, byte-aligned string, without inspecting contents.
    pub const fn bytes(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            valid_bits: if bytes.is_empty() { 0 } else { 8 },
        }
    }
}

/// Public per-operation and per-mapping limits; not a process-wide quota.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Worker stack reservation, at least 64 KiB.
    pub stack_bytes: usize,
    /// Stack bound accounting for page rounding and two guards.
    pub max_stack_mapping_bytes: usize,
    /// Output bound accounting for page rounding and two guards.
    pub max_output_mapping_bytes: usize,
    /// Combined message bits, excluding N/S.
    pub max_message_bits: u128,
    /// Combined N/S bits. Prefix setup is bounded but not internally cancellable.
    pub max_customization_bits: usize,
    /// Exact output-bit budget; zero permits only empty XOF output.
    pub max_output_bits: usize,
    /// Bounds even lists consisting entirely of empty chunks; must be nonzero.
    pub max_chunks: usize,
}

/// Public failure categories; never private accumulated state or contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Required platform, storage or worker protection failed.
    Resource(protected_memory::Error),
    /// Configuration cannot admit any chunk list.
    InvalidLimits,
    /// Request exceeds an explicit public budget.
    WorkLimit,
    /// Checked length arithmetic failed.
    MessageTooLong,
    /// Bit count or unused high bits are invalid.
    InvalidBits,
    /// Nonempty N/S supplied to a non-cSHAKE algorithm.
    Customization,
    /// Cooperative cancellation was observed.
    Cancelled,
    /// Public declassification destination has the wrong width.
    OutputLength,
    /// Internal scoped-state or transfer invariant failed.
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
            Self::Resource(_) => "strict SHA-3 resource failed",
            Self::InvalidLimits => "strict SHA-3 invalid limits",
            Self::WorkLimit => "strict SHA-3 work limit exceeded",
            Self::MessageTooLong => "strict SHA-3 length domain exceeded",
            Self::InvalidBits => "strict SHA-3 noncanonical bits",
            Self::Customization => "strict SHA-3 unexpected customization",
            Self::Cancelled => "strict SHA-3 cancelled",
            Self::OutputLength => "strict SHA-3 output width mismatch",
            Self::Invariant => "strict SHA-3 invariant failed",
        })
    }
}
impl std::error::Error for Error {}

/// One-way cooperative cancellation, never forcible native thread cancellation.
#[derive(Default)]
pub struct Cancellation(AtomicBool);
impl Cancellation {
    /// An unset flag.
    pub const fn new() -> Self {
        Self(AtomicBool::new(false))
    }
    /// Request cancellation; cannot be reset.
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
