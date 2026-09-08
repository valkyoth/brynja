/// Exact kernel identity, including algorithm and vector workload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Backend {
    /// Single SHA-224/256 stream, x86_64 SHA.
    X86Sha256,
    /// Single SHA-224/256 stream, AArch64 SHA2.
    ArmSha256,
    /// Single SHA-224/256 stream, RV64 Zknh.
    RvSha256,
    /// Single SHA-512-family stream, AArch64 SHA512.
    ArmSha512,
    /// Single SHA-512-family stream, RV64 Zknh.
    RvSha512,
    /// Single Keccak state, x86_64 AVX2; NOT independent-message batching.
    X86Keccak,
    /// Single Keccak state, AArch64 SHA3.
    ArmKeccak,
    /// Legacy SHA-1 stream, x86 SHA.
    LegacyX86Sha1,
    /// Legacy SHA-1 stream, little-endian AArch64 SHA1.
    LegacyArmSha1,
    /// Legacy MD5, eight independent messages, x86_64 AVX2.
    LegacyX86Md5x8,
    /// Legacy MD5, four independent messages, little-endian AArch64 NEON.
    LegacyArmMd5x4,
}

impl Backend {
    /// Fixed model inventory; it confers no availability or feature authority.
    pub const ALL: [Self; 11] = [
        Self::X86Sha256,
        Self::ArmSha256,
        Self::RvSha256,
        Self::ArmSha512,
        Self::RvSha512,
        Self::X86Keccak,
        Self::ArmKeccak,
        Self::LegacyX86Sha1,
        Self::LegacyArmSha1,
        Self::LegacyX86Md5x8,
        Self::LegacyArmMd5x4,
    ];
}

/// Requested ownership profile; a request is NOT a hardened capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    /// Public-data algorithm state.
    Ordinary,
    /// Requires an algorithm's separately sealed secret-owning API.
    Hardened,
}

/// Caller intent. Cargo features and requests never prove CPU support.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request {
    /// Never attempt acceleration, even when available.
    Portable,
    /// Try exactly this kernel/profile; report pre-execution fallback.
    Prefer(Backend, Profile),
    /// Use exactly this kernel/profile or return a typed failure.
    Require(Backend, Profile),
}

/// Closed model errors; production APIs will preserve algorithm-specific errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Implementation or normal downstream integration is incomplete.
    NotOperational,
    /// Architecture, full feature bundle, OS state or migration contract missing.
    UnsupportedPlatform,
    /// The requested hardened profile lacks equivalent cleanup evidence/API.
    UnsupportedProfile,
    /// KAT or integrity failure permanently quarantined the session.
    Quarantined,
    /// An established execution lease was lost; no implicit state transfer.
    AuthorityLost,
}

/// Exact request and reason retained when preference falls back before use.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fallback {
    /// Requested kernel; never replaced by a different accelerated kernel.
    pub backend: Backend,
    /// Requested ownership profile.
    pub profile: Profile,
    /// Why the portable route was selected.
    pub reason: Error,
}

/// Observational model route, never accepted as production execution authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    /// Portable route, with explicit preference fallback when applicable.
    Portable(Option<Fallback>),
    /// Hypothetical accelerated route; unreachable via this model's public begin.
    Accelerated(Backend, Profile),
}
