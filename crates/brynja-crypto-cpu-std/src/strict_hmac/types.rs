use super::Algorithm;
use crate::protected_memory;
use std::sync::atomic::{AtomicBool, Ordering};

/// Protocol-selected tag width, never inferred from a supplied candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TagPolicy {
    /// Exact complete digest, including a general SHA-512/t partial byte.
    Full,
    /// Whole-byte prefix, at least 16 bytes and no longer than the digest.
    Bytes(usize),
}
impl TagPolicy {
    pub(super) fn bits<A: Algorithm>(self) -> Result<usize, Error> {
        let selected = match self {
            Self::Full => None,
            Self::Bytes(bytes) => Some(bytes),
        };
        brynja_mac_hmac::validate_tag_policy::<A>(selected).map_err(|error| match error {
            brynja_mac_hmac::Error::TagLength => Error::InvalidTagPolicy,
            other => Error::Mac(other),
        })
    }
}

/// Raw final-message bits, validated only on the protected worker.
///
/// SHA-2 uses high bits and SHA-3 uses low bits in the final byte.
/// Unused bits must be zero. Original input remains caller-owned.
#[derive(Clone, Copy)]
pub struct Bits<'a> {
    /// Borrowed input; never copied into the worker's ordinary launch record.
    pub bytes: &'a [u8],
    /// Zero for empty input, otherwise 1..=8.
    pub valid_bits: u8,
}
impl<'a> Bits<'a> {
    /// Canonical empty tail.
    pub const fn empty() -> Self {
        Self {
            bytes: &[],
            valid_bits: 0,
        }
    }
    /// Byte-aligned borrowed tail, without inspecting contents.
    pub const fn bytes(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            valid_bits: if bytes.is_empty() { 0 } else { 8 },
        }
    }
    pub(super) fn bit_len(self) -> Result<u128, Error> {
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

/// Complete borrowed request. The session retains no key or message between calls.
pub struct Request<'a> {
    /// Byte-string key. Length is bounded, but entropy cannot be verified.
    /// Empty/predictable keys are mathematically accepted and insecure.
    pub key: &'a [u8],
    /// Byte-aligned chunks in message order; empty chunks count toward the budget.
    pub chunks: &'a [&'a [u8]],
    /// Final message bytes/bits, following every chunk.
    pub tail: Bits<'a>,
}

/// Independent resource and public work limits; no process-wide quota.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Protected worker stack; at least 64 KiB (not a sufficiency proof).
    pub stack_bytes: usize,
    /// Stack reservation budget, including guards and page rounding.
    pub max_stack_mapping_bytes: usize,
    /// Separate budget for each of staging and retained output.
    pub max_buffer_mapping_bytes: usize,
    /// Key setup is bounded but is not internally cancellable.
    pub max_key_bytes: usize,
    /// Maximum complete request message width.
    pub max_message_bits: u128,
    /// Maximum chunk count; must be nonzero.
    pub max_chunks: usize,
}

/// Public failure categories; no key, accumulated state or private diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Required platform resource failed; never permits ordinary-stack fallback.
    Resource(protected_memory::Error),
    /// Invalid limits.
    InvalidLimits,
    /// Tag width not admitted by the selected HMAC algorithm.
    InvalidTagPolicy,
    /// Public request budget exceeded.
    WorkLimit,
    /// Noncanonical message bit shape/content.
    InvalidBits,
    /// Destination/candidate width differs from the preselected width.
    OutputLength,
    /// Cooperative cancellation observed.
    Cancelled,
    /// Hardened HMAC construction/execution failure.
    Mac(brynja_mac_hmac::Error),
    /// Explicit accelerated session permanently rejected further requests.
    #[cfg(feature = "strict-hmac-acceleration")]
    Quarantined,
    /// Required compiled backend could not be admitted; no scalar fallback.
    #[cfg(feature = "strict-hmac-acceleration")]
    Backend(brynja_crypto_cpu::static_execution::Error),
    /// Internal transfer/result invariant failed.
    Invariant,
    /// Completed authentication mismatch; the session remains reusable.
    Mismatch,
}
impl From<protected_memory::Error> for Error {
    fn from(error: protected_memory::Error) -> Self {
        Self::Resource(error)
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("protected HMAC operation failed")
    }
}
impl std::error::Error for Error {}

/// One-way cooperative cancellation, not native thread cancellation.
#[derive(Default)]
pub struct Cancellation(AtomicBool);
impl Cancellation {
    /// Initially not cancelled.
    pub const fn new() -> Self {
        Self(AtomicBool::new(false))
    }
    /// Requests cancellation at the next worker checkpoint.
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

/// Explicit release of a retained secret result as a public tag.
pub struct PublicDeclassification(());
impl PublicDeclassification {
    /// Caller asserts that the complete selected tag may be made public.
    pub const fn acknowledge() -> Self {
        Self(())
    }
}

pub(super) fn validate(
    limits: Limits,
    request: &Request<'_>,
    candidate: Option<&[u8]>,
    tag_bytes: usize,
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
    if candidate.is_some_and(|value| value.len() != tag_bytes) {
        return Err(Error::OutputLength);
    }
    Ok(())
}
