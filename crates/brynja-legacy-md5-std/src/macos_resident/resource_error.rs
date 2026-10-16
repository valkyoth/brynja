/// Public failure without secret contents. No error authorizes weaker fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ResourceError {
    /// Not native little-endian 64-bit Apple Silicon macOS.
    Unsupported,
    /// Invalid or overflowing geometry/configuration.
    InvalidSize,
    /// Mapping reservation exceeds the caller's bound.
    ResourceLimit,
    /// Anonymous guarded mapping could not be reserved.
    Mapping,
    /// Fork-inheritance exclusion could not be acquired.
    ForkExclusion,
    /// Payload access protection could not be set.
    Access,
    /// Resident-page locking failed.
    Lock,
    /// Cleared mapping could not be released.
    Release,
    /// Native worker attributes could not be configured.
    ThreadAttributes,
    /// Native worker creation failed.
    ThreadStart,
    /// Worker panicked; join and owned-stack clearing completed.
    WorkerPanicked,
    /// Worker returned without completing the library operation.
    WorkerProtocol,
    /// Reserved public resource work-limit outcome.
    WorkLimit,
    /// Internal hash/transfer invariant failed.
    Invariant,
}
impl core::fmt::Display for ResourceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "macOS resident profile: {self:?}")
    }
}
impl std::error::Error for ResourceError {}
