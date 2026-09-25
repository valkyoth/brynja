use crate::protected_memory;
pub use brynja_hash_tuple::TupleHashPublicDeclassification as PublicDeclassification;
use std::sync::atomic::{AtomicBool, Ordering};

/// Public construction and exact output-bit count, including zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    /// Fixed TupleHash128; output length participates in domain separation.
    TupleHash128(usize),
    /// Fixed TupleHash256; output length participates in domain separation.
    TupleHash256(usize),
    /// TupleHashXOF128, distinct from fixed output even at equal widths.
    TupleHashXof128(usize),
    /// TupleHashXOF256, distinct from fixed output even at equal widths.
    TupleHashXof256(usize),
}
impl Algorithm {
    /// Exact public output width, never private accumulated state.
    pub const fn output_bits(self) -> usize {
        match self {
            Self::TupleHash128(n)
            | Self::TupleHash256(n)
            | Self::TupleHashXof128(n)
            | Self::TupleHashXof256(n) => n,
        }
    }
    /// Required canonical bytes; unused high bits of the final byte are zero.
    pub const fn output_bytes(self) -> usize {
        self.output_bits().div_ceil(8)
    }
    pub(super) const fn xof(self) -> bool {
        matches!(self, Self::TupleHashXof128(_) | Self::TupleHashXof256(_))
    }
}

/// Raw borrowed LSB-first bits. Canonicality is checked on the protected worker.
pub struct Bits<'a> {
    /// Original caller storage remains the caller's responsibility.
    pub bytes: &'a [u8],
    /// Zero for empty; otherwise 1..=8 with unused high bits zero.
    pub valid_bits: u8,
}
impl<'a> Bits<'a> {
    /// Empty bit string.
    pub const fn empty() -> Self {
        Self {
            bytes: &[],
            valid_bits: 0,
        }
    }
    /// Byte-aligned borrow without inspecting its contents.
    pub const fn bytes(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            valid_bits: if bytes.is_empty() { 0 } else { 8 },
        }
    }
}
/// Exactly one tuple element, not one element per chunk. Empty elements count.
/// Item length is derived with checked arithmetic; it cannot be caller-forged.
pub struct Item<'a> {
    /// Byte-aligned fragments belonging to this single item.
    pub chunks: &'a [&'a [u8]],
    /// Final bits of this item, following all fragments.
    pub tail: Bits<'a>,
}
impl<'a> Item<'a> {
    /// One byte-aligned item without allocating a fragment list.
    pub const fn bytes(bytes: &'a [u8]) -> Self {
        Self {
            chunks: &[],
            tail: Bits::bytes(bytes),
        }
    }
}

/// Explicit per-resource and complete-request limits, not a process-wide quota.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Protected worker stack reservation, at least 64 KiB.
    pub stack_bytes: usize,
    /// Stack mapping budget accounting for guards and rounding.
    pub max_stack_mapping_bytes: usize,
    /// Separate budget for each of staging and output, with guards and rounding.
    pub max_buffer_mapping_bytes: usize,
    /// Sum of all item bits, excluding framing and customization.
    pub max_input_bits: u128,
    /// Customization-bit budget; prefix setup is not internally cancellable.
    pub max_customization_bits: usize,
    /// Exact output-bit budget.
    pub max_output_bits: usize,
    /// Tuple element budget, including empty elements; zero allows empty tuples.
    pub max_items: usize,
    /// Total explicit fragment descriptors, including empty fragments.
    pub max_chunks: usize,
}
/// Public outcome only, with no secret bytes or accumulated-state queries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Required OS, target or worker protection failed.
    Resource(protected_memory::Error),
    /// A public request budget was exceeded.
    WorkLimit,
    /// Checked length arithmetic failed.
    MessageTooLong,
    /// Noncanonical bit shape or unused high bits.
    InvalidBits,
    /// Public destination width does not match the session.
    OutputLength,
    /// Cooperative cancellation was observed.
    Cancelled,
    /// Scoped framing, completion or transfer invariant failed.
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
            Self::Resource(_) => "strict TupleHash protected resource failed",
            Self::WorkLimit => "strict TupleHash work limit exceeded",
            Self::MessageTooLong => "strict TupleHash length domain exceeded",
            Self::InvalidBits => "strict TupleHash noncanonical bits",
            Self::OutputLength => "strict TupleHash output width mismatch",
            Self::Cancelled => "strict TupleHash cancelled",
            Self::Invariant => "strict TupleHash invariant failed",
        })
    }
}
impl std::error::Error for Error {}
/// One-way cooperative cancellation, never native-thread cancellation.
#[derive(Default)]
pub struct Cancellation(AtomicBool);
impl Cancellation {
    /// An unset flag.
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
