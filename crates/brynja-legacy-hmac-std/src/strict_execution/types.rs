use brynja_crypto_cpu_std::protected_memory;
use brynja_legacy_hmac::Algorithm;
use std::sync::atomic::{AtomicBool, Ordering};

/// Preselected legacy tag width. Never infer this policy from an incoming tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TagPolicy {
    /// Full 20-byte SHA-1 or 16-byte MD5 output.
    Full,
    /// Whole-byte prefix, at least ten bytes and at most the full digest width.
    Bytes(usize),
}
impl TagPolicy {
    pub(super) fn bytes<A: Algorithm>(self) -> Result<usize, Error> {
        let bytes = match self {
            Self::Full => A::TAG_BYTES,
            Self::Bytes(n) => n,
        };
        if !(10..=A::TAG_BYTES).contains(&bytes) {
            return Err(Error::InvalidTagPolicy);
        }
        Ok(bytes)
    }
}

/// Borrowed canonical MSB-first final message bits; content is checked on worker.
#[derive(Clone, Copy)]
pub struct Bits<'a> {
    /// Original bytes remain caller-owned, not silently migrated into protected memory.
    pub bytes: &'a [u8],
    /// Zero for empty input, otherwise 1..=8 high bits in the last byte.
    pub valid_bits: u8,
}
impl<'a> Bits<'a> {
    /// Empty canonical tail.
    pub const fn empty() -> Self {
        Self {
            bytes: &[],
            valid_bits: 0,
        }
    }
    /// Byte-aligned tail without inspecting its contents on the host.
    pub const fn bytes(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            valid_bits: if bytes.is_empty() { 0 } else { 8 },
        }
    }
    fn bit_len(self) -> Result<u128, Error> {
        if self.bytes.is_empty() {
            return if self.valid_bits == 0 {
                Ok(0)
            } else {
                Err(Error::InvalidBits)
            };
        }
        if !(1..=8).contains(&self.valid_bits) {
            return Err(Error::InvalidBits);
        }
        (self.bytes.len() as u128)
            .checked_sub(1)
            .and_then(|n| n.checked_mul(8))
            .and_then(|n| n.checked_add(u128::from(self.valid_bits)))
            .ok_or(Error::WorkLimit)
    }
}

/// Complete borrowed operation. Only pointers/lengths enter the launch closure;
/// all HMAC state and intermediate key/digest bytes are created on the worker.
pub struct Request<'a> {
    /// Key entropy cannot be verified. Empty/predictable keys are insecure.
    pub key: &'a [u8],
    /// Ordered byte chunks; empty entries still count toward the chunk budget.
    pub chunks: &'a [&'a [u8]],
    /// Final bytes/bits appended after the chunks.
    pub tail: Bits<'a>,
}

/// Public resource/work bounds; not a process-wide quota or stack-depth proof.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Worker stack reservation; minimum 64 KiB is only an allocation floor.
    pub stack_bytes: usize,
    /// Maximum stack mapping including guards/page rounding.
    pub max_stack_mapping_bytes: usize,
    /// Maximum individual staging/output mapping including guards/page rounding.
    pub max_buffer_mapping_bytes: usize,
    /// Maximum key length; normalization is bounded but not internally cancellable.
    pub max_key_bytes: usize,
    /// Maximum complete message bits across all chunks and the tail.
    pub max_message_bits: u128,
    /// Maximum number of byte chunks, including empty entries; must be nonzero.
    pub max_chunks: usize,
}

/// Value-free failure. No variant authorizes a weaker fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Required native protection or joined worker failed.
    Resource(protected_memory::Error),
    /// Invalid resource/work configuration.
    InvalidLimits,
    /// Tag policy is outside the selected legacy algorithm's domain.
    InvalidTagPolicy,
    /// Public key/message/chunk budget exceeded.
    WorkLimit,
    /// Invalid bit shape or nonzero unused tail bits.
    InvalidBits,
    /// Output or candidate does not match the preselected tag width.
    OutputLength,
    /// Cooperative cancellation was observed.
    Cancelled,
    /// Underlying isolated legacy HMAC failed.
    Mac(brynja_legacy_hmac::Error),
    /// Private worker transfer/result invariant failed.
    Invariant,
}
impl From<protected_memory::Error> for Error {
    fn from(e: protected_memory::Error) -> Self {
        Self::Resource(e)
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("protected legacy HMAC operation failed")
    }
}
impl std::error::Error for Error {}

/// One-way cooperative cancellation; never native thread cancellation.
#[derive(Default)]
pub struct Cancellation(AtomicBool);
impl Cancellation {
    /// Starts with no request to cancel.
    pub const fn new() -> Self {
        Self(AtomicBool::new(false))
    }
    /// Requests cancellation at the next checkpoint.
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

/// Explicit caller-authorized release of a secret tag as public bytes.
pub struct PublicDeclassification(());
impl PublicDeclassification {
    /// Acknowledges public release; does not certify protocol suitability.
    pub const fn acknowledge() -> Self {
        Self(())
    }
}

pub(super) fn validate(
    limits: Limits,
    request: &Request<'_>,
    candidate: Option<&[u8]>,
    bytes: usize,
) -> Result<(), Error> {
    if request.key.len() > limits.max_key_bytes || request.chunks.len() > limits.max_chunks {
        return Err(Error::WorkLimit);
    }
    let mut bits = request.tail.bit_len()?;
    for chunk in request.chunks {
        bits = (chunk.len() as u128)
            .checked_mul(8)
            .and_then(|n| bits.checked_add(n))
            .ok_or(Error::WorkLimit)?;
    }
    if bits > limits.max_message_bits {
        return Err(Error::WorkLimit);
    }
    if candidate.is_some_and(|value| value.len() != bytes) {
        return Err(Error::OutputLength);
    }
    Ok(())
}
