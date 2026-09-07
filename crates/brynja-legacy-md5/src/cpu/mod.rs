#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
mod aarch64_neon_md5;
#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_endian = "little")
))]
mod constants;
mod kat;
mod session;
#[cfg(target_arch = "x86_64")]
mod x86_avx2_md5;

pub use session::Md5BackendSession;

/// Independent-message SIMD family; neither a modern nor a FIPS capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Md5Backend {
    /// Eight independent MD5 messages using AVX2, not dedicated MD5 instructions.
    X86Avx2,
    /// Four independent MD5 messages using little-endian AArch64 NEON.
    Aarch64Neon,
}
impl Md5Backend {
    /// Stable, non-authorizing diagnostic identity.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X86Avx2 => "legacy-x86_64-avx2-md5",
            Self::Aarch64Neon => "legacy-aarch64-neon-md5",
        }
    }
    /// Number of independent messages required per instruction invocation.
    pub const fn lane_width(self) -> usize {
        match self {
            Self::X86Avx2 => 8,
            Self::Aarch64Neon => 4,
        }
    }
    /// Exact feature bundle; AVX2 also requires OS-enabled YMM context support.
    pub const fn required_features(self) -> &'static [&'static str] {
        match self {
            Self::X86Avx2 => &["avx2"],
            Self::Aarch64Neon => &["neon"],
        }
    }
    /// No backend is admitted. Changing this flag is not an admission design.
    pub const fn is_admitted(self) -> bool {
        false
    }
}

/// Non-authorizing health of this caller-owned session only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Md5BackendHealth {
    /// The actual multi-lane instruction KAT passed.
    Healthy,
    /// Permanent failure; this session cannot be reset.
    Quarantined,
}

/// Closed errors returned before caller-state mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Md5BackendError {
    /// Target architecture/endianness has no matching compiled kernel.
    WrongArchitecture,
    /// Exact migration-safe instruction/OS support is missing or was lost.
    MissingFeatures,
    /// Evidence does not authorize production execution.
    NotAdmitted,
    /// KAT or execution authority permanently failed for this session.
    Quarantined,
}
