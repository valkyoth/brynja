#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
mod aarch64_sha1;
mod session;
mod stream;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86_sha1;

pub use session::Sha1BackendSession;
pub use stream::AcceleratedSha1;

/// Isolated legacy SHA-1 instruction family; never a modern/FIPS capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Sha1Backend {
    /// x86 or x86_64 SHA and SSE2 instructions.
    X86Sha,
    /// Little-endian AArch64 SHA1 instructions (Rust's `sha2` feature bundle).
    Aarch64Sha1,
}

impl Sha1Backend {
    /// Stable identity for non-authorizing evidence and diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X86Sha => "legacy-x86-sha1",
            Self::Aarch64Sha1 => "legacy-aarch64-sha1",
        }
    }

    /// Exact compiler feature bundle. AArch64 `sha2` includes SHA1 intrinsics.
    pub const fn required_features(self) -> &'static [&'static str] {
        match self {
            Self::X86Sha => &["sse2", "sha"],
            Self::Aarch64Sha1 => &["neon", "sha2"],
        }
    }

    /// No candidate has native correctness/migration/timing admission yet.
    pub const fn is_admitted(self) -> bool {
        false
    }
}

/// Non-authorizing current health of a caller-owned legacy session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Sha1BackendHealth {
    /// Direct instruction-kernel startup KAT passed.
    Healthy,
    /// Permanent failure of this session; it cannot be reset.
    Quarantined,
}

/// Closed errors; no digest is produced on a failed backend operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Sha1BackendError {
    /// No backend is compiled for this architecture/endianness.
    WrongArchitecture,
    /// Exact feature proof is absent or was lost during revalidation.
    MissingFeatures,
    /// Native evidence does not authorize this candidate.
    NotAdmitted,
    /// Startup KAT or per-operation revalidation permanently failed.
    Quarantined,
    /// The FIPS 180-4 message bit domain would be exceeded.
    MessageTooLong,
}
