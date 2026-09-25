use crate::protected_memory;
pub(super) use brynja_hash_sha2::hardened_batch as sha256;
pub(super) use brynja_hash_sha2::hardened_batch512 as sha512;
pub(super) use brynja_hash_sha3::hardened_batch as keccak;
use std::sync::atomic::{AtomicBool, Ordering};
/// One-way cooperative cancellation, never native-thread cancellation.
#[derive(Default)]
pub struct Cancellation(AtomicBool);
impl Cancellation {
    /// Initially unset.
    pub const fn new() -> Self {
        Self(AtomicBool::new(false))
    }
    /// Requests cancellation at a bounded library checkpoint.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    /// Public cancellation state, never hash-derived metadata.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Exact family and execution choice. Portable is explicit, never a failure fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    /// Eight-slot SHA-224/256; None explicitly chooses protected portable execution.
    Sha256(Option<sha256::Kernel>),
    /// Four-slot SHA-512 family, including all valid general t parameters.
    Sha512(Option<sha512::Kernel>),
    /// Four-slot SHA-3/SHAKE/cSHAKE with caller-bounded finite output.
    Keccak(Option<keccak::Kernel>),
}
impl Route {
    pub(super) const fn capacity(self) -> usize {
        match self {
            Self::Sha256(_) => 8,
            _ => 4,
        }
    }
}
/// Exact public identity. Keccak identities retain the exact finite output bits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    /// SHA-224 or SHA-256.
    Sha256(sha256::Algorithm),
    /// Named/general SHA-512 identity.
    Sha512(sha512::Algorithm),
    /// SHA-3 exact fixed width or caller-selected SHAKE/cSHAKE width.
    Keccak(keccak::Algorithm, usize),
}
impl Algorithm {
    /// Exact byte width, including one canonical partial last byte when needed.
    pub const fn output_bytes(self) -> usize {
        match self {
            Self::Sha256(a) => a.output_bytes(),
            Self::Sha512(a) => a.output_bytes(),
            Self::Keccak(_, bits) => bits.div_ceil(8),
        }
    }
}
/// Borrowed unvalidated bits. SHA-2 is MSB-first; Keccak-family input is LSB-first.
pub struct Bits<'a> {
    /// Original input and copies remain caller-owned.
    pub bytes: &'a [u8],
    /// Zero for empty; otherwise 1..=8 with unused bits zero.
    pub valid_bits: u8,
}
impl<'a> Bits<'a> {
    /// Byte-aligned borrow with no content inspection.
    pub const fn bytes(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            valid_bits: if bytes.is_empty() { 0 } else { 8 },
        }
    }
}
/// Complete request for one independent slot; not a public-data assertion.
pub struct Input<'a> {
    /// Exact identity and output width.
    pub algorithm: Algorithm,
    /// Canonicality is checked only on the protected worker.
    pub message: Bits<'a>,
    /// cSHAKE N; must be empty for other identities.
    pub name: Bits<'a>,
    /// cSHAKE S; must be empty for other identities.
    pub customization: Bits<'a>,
}
impl<'a> Input<'a> {
    /// Byte message, with empty N/S.
    pub const fn bytes(algorithm: Algorithm, message: &'a [u8]) -> Self {
        Self {
            algorithm,
            message: Bits::bytes(message),
            name: Bits::bytes(&[]),
            customization: Bits::bytes(&[]),
        }
    }
}
/// Preacquired per-resource limits and per-request aggregate byte bounds.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// At least 64 KiB; all state/staging/callbacks are library-controlled.
    pub stack_bytes: usize,
    /// Stack guards/rounding included in this bound.
    pub max_stack_mapping_bytes: usize,
    /// Separate bound for each output, intermediate and scratch mapping.
    pub max_buffer_mapping_bytes: usize,
    /// Sum of message bytes, including any partial last byte.
    pub max_input_bytes: usize,
    /// Sum of N/S bytes across all slots.
    pub max_customization_bytes: usize,
    /// Sum of rounded output bytes, acquired before input.
    pub max_output_bytes: usize,
}
/// Value-free, finite failure classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Unsupported protected platform/model or resource/thread failure.
    Resource(protected_memory::Error),
    /// Family, active-slot, identity, bit or output descriptor mismatch.
    InvalidInput,
    /// Public bound exceeded, including checked aggregate arithmetic.
    WorkLimit,
    /// Cooperative cancellation observed.
    Cancelled,
    /// Required SHA-224/256 authority or computation rejected.
    Sha256(sha256::Error),
    /// Required SHA-512-family authority or computation rejected.
    Sha512(sha512::Error),
    /// Required Keccak authority or computation rejected.
    Keccak(keccak::Error),
    /// This wrapper is permanently revoked.
    Quarantined,
    /// Internal route/output invariant failed.
    Invariant,
}
impl From<protected_memory::Error> for Error {
    fn from(e: protected_memory::Error) -> Self {
        Self::Resource(e)
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("strict protected batch rejected")
    }
}
impl std::error::Error for Error {}
/// Actual performed work; lengths/slot activity are public, never secret digests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Report {
    /// SHA-224/256 work.
    Sha256(sha256::Report),
    /// SHA-512-family work.
    Sha512(sha512::Report),
    /// Keccak permutations.
    Keccak(keccak::Report),
}
pub(super) fn reusable(result: &Result<Report, Error>) -> bool {
    matches!(
        result,
        Ok(_)
            | Err(Error::InvalidInput | Error::WorkLimit | Error::Cancelled)
            | Err(Error::Sha256(
                sha256::Error::IneligibleWorkload
                    | sha256::Error::MessageTooLong
                    | sha256::Error::WorkLimit
                    | sha256::Error::Cancelled
            ))
            | Err(Error::Sha512(
                sha512::Error::IneligibleWorkload
                    | sha512::Error::MessageTooLong
                    | sha512::Error::WorkLimit
                    | sha512::Error::Cancelled
            ))
            | Err(Error::Keccak(
                keccak::Error::IneligibleWorkload
                    | keccak::Error::MessageTooLong
                    | keccak::Error::WorkLimit
                    | keccak::Error::Cancelled
            ))
    )
}
