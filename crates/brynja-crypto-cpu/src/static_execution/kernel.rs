use super::Error;

/// Exact ordinary kernel selected by a target-specialized executable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Kernel {
    /// x86_64 SHA-256 instructions with SSE2 register state.
    X86Sha256,
    /// AArch64 NEON and SHA2 instructions.
    ArmSha256,
    /// AArch64 NEON and the complete Rust SHA3/SHA512 bundle.
    ArmSha512,
    /// x86_64 AVX2 single-state Keccak; requires enabled XMM/YMM OS state.
    X86Keccak,
    /// AArch64 NEON and SHA3 Keccak instructions.
    ArmKeccak,
}

impl Kernel {
    /// All static kernels supported by this boundary, not by every target.
    pub const ALL: [Self; 5] = [
        Self::X86Sha256,
        Self::ArmSha256,
        Self::ArmSha512,
        Self::X86Keccak,
        Self::ArmKeccak,
    ];

    /// Checks the compiler's complete target bundle, never runtime CPUID.
    ///
    /// The executable must run only on compatible CPUs with the required OS
    /// register state for its entire lifetime. This does not establish that
    /// an arbitrary host is compatible with the compiled executable.
    pub const fn check_compiled_target(self) -> Result<(), Error> {
        let (architecture, features) = match self {
            Self::X86Sha256 => (
                cfg!(target_arch = "x86_64"),
                cfg!(all(target_feature = "sha", target_feature = "sse2")),
            ),
            Self::ArmSha256 => (
                cfg!(target_arch = "aarch64"),
                cfg!(all(target_feature = "neon", target_feature = "sha2")),
            ),
            Self::ArmSha512 | Self::ArmKeccak => (
                cfg!(target_arch = "aarch64"),
                cfg!(all(target_feature = "neon", target_feature = "sha3")),
            ),
            Self::X86Keccak => (
                cfg!(target_arch = "x86_64"),
                cfg!(all(target_feature = "avx", target_feature = "avx2")),
            ),
        };
        if !architecture {
            return Err(Error::WrongArchitecture);
        }
        if !features {
            return Err(Error::MissingTargetFeatures);
        }
        Ok(())
    }
}
