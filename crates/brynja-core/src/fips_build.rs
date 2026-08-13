//! Deterministic build expectations for a future FIPS module.

/// A deterministic-build expectation failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum FipsBuildError {
    /// One required manifest digest was the reserved all-zero value.
    EmptyDigest,
}

/// Immutable deterministic-build inputs for a future module.
///
/// These digests describe expectations only. The final validated artifact
/// identity remains unfrozen until its later roadmap milestone.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FipsBuildExpectations {
    source: [u8; 32],
    toolchain: [u8; 32],
    flags: [u8; 32],
    dependencies: [u8; 32],
}

impl FipsBuildExpectations {
    /// Requires nonzero digests for all deterministic inputs.
    pub fn new(
        source: [u8; 32],
        toolchain: [u8; 32],
        flags: [u8; 32],
        dependencies: [u8; 32],
    ) -> Result<Self, FipsBuildError> {
        if [source, toolchain, flags, dependencies].contains(&[0; 32]) {
            Err(FipsBuildError::EmptyDigest)
        } else {
            Ok(Self {
                source,
                toolchain,
                flags,
                dependencies,
            })
        }
    }

    /// Returns the exact expected first-party source digest.
    #[must_use]
    pub const fn source(&self) -> &[u8; 32] {
        &self.source
    }

    /// Returns the exact expected Rust toolchain digest.
    #[must_use]
    pub const fn toolchain(&self) -> &[u8; 32] {
        &self.toolchain
    }

    /// Returns the exact expected build-flags digest.
    #[must_use]
    pub const fn flags(&self) -> &[u8; 32] {
        &self.flags
    }

    /// Returns the exact expected dependency-closure digest.
    #[must_use]
    pub const fn dependencies(&self) -> &[u8; 32] {
        &self.dependencies
    }
}
