use brynja_crypto_cpu_std::protected_memory;
pub use brynja_hash_parallel::ParallelHashPublicDeclassification as PublicDeclassification;

/// Exact public construction and output width; fixed and XOF are distinct.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    /// Fixed ParallelHash128.
    ParallelHash128(usize),
    /// Fixed ParallelHash256.
    ParallelHash256(usize),
    /// ParallelHashXOF128.
    ParallelHashXof128(usize),
    /// ParallelHashXOF256.
    ParallelHashXof256(usize),
}
impl Algorithm {
    /// Public output-bit count, not accumulated secret state.
    pub const fn output_bits(self) -> usize {
        match self {
            Self::ParallelHash128(n)
            | Self::ParallelHash256(n)
            | Self::ParallelHashXof128(n)
            | Self::ParallelHashXof256(n) => n,
        }
    }
    /// Canonical output bytes, rounded up without overflowing.
    pub const fn output_bytes(self) -> usize {
        self.output_bits().div_ceil(8)
    }
    pub(super) const fn wide(self) -> bool {
        matches!(self, Self::ParallelHash256(_) | Self::ParallelHashXof256(_))
    }
    pub(super) const fn xof(self) -> bool {
        matches!(
            self,
            Self::ParallelHashXof128(_) | Self::ParallelHashXof256(_)
        )
    }
}
/// Raw LSB-first input. Content validation runs on a protected stack.
pub struct Bits<'a> {
    /// Borrowed original input; protecting caller storage remains caller-owned.
    pub bytes: &'a [u8],
    /// Zero for empty input, otherwise 1..=8; unused high bits must be zero.
    pub valid_bits: u8,
}
impl<'a> Bits<'a> {
    /// Byte-aligned input, without inspecting its contents.
    pub const fn bytes(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            valid_bits: if bytes.is_empty() { 0 } else { 8 },
        }
    }
}
/// Preacquired per-resource limits. The root uses one additional worker stack.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Concurrent leaf workers, 1..=64.
    pub workers: usize,
    /// Maximum leaves; all CV slots are protected before any input is accepted.
    pub max_leaves: usize,
    /// Positive maximum block size B; each leaf is one cancellation interval.
    pub max_block_bytes: usize,
    /// Maximum customization bytes; prefix setup is not internally cancellable.
    pub max_customization_bytes: usize,
    /// Maximum output-bit count.
    pub max_output_bits: usize,
    /// Each worker/root stack reservation, at least 64 KiB.
    pub stack_bytes: usize,
    /// Each stack's mapping budget, including guard pages and rounding.
    pub max_stack_mapping_bytes: usize,
    /// Separate budget for CV storage, staging and output, including guards.
    pub max_buffer_mapping_bytes: usize,
}
/// Public failure without secret payloads. No ordinary-memory fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// OS, target, allocation or native worker failure.
    Resource(protected_memory::Error),
    /// Invalid configuration or request budget exceeded.
    WorkLimit,
    /// Invalid canonical input bits.
    InvalidBits,
    /// Cooperative cancellation observed.
    Cancelled,
    /// Exact-plan/framing/transfer invariant failed.
    Invariant,
    /// Explicit public destination has the wrong length.
    OutputLength,
}
impl From<protected_memory::Error> for Error {
    fn from(value: protected_memory::Error) -> Self {
        Self::Resource(value)
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Resource(_) => "strict ParallelHash protected resource failed",
            Self::WorkLimit => "strict ParallelHash work limit exceeded",
            Self::InvalidBits => "strict ParallelHash noncanonical bits",
            Self::Cancelled => "strict ParallelHash cancelled",
            Self::Invariant => "strict ParallelHash invariant failed",
            Self::OutputLength => "strict ParallelHash output width mismatch",
        })
    }
}
impl std::error::Error for Error {}
