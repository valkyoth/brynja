//! Secret-free provider failure classification.

/// A future provider operation category.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ProviderOperation {
    /// Obtain entropy.
    Entropy,
    /// Perform a key agreement.
    KeyAgreement,
    /// Produce a signature.
    Sign,
    /// Verify a signature.
    Verify,
    /// Perform an AEAD operation.
    Aead,
    /// Access persistent storage.
    Storage,
    /// Read a trusted clock.
    Clock,
}

/// A provider failure class that does not expose provider text or codes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ProviderFailureKind {
    /// The capability is unavailable.
    Unavailable,
    /// The provider rejected the operation.
    Rejected,
    /// The provider returned structurally invalid output.
    InvalidOutput,
    /// The operation was canceled before commitment.
    Canceled,
    /// The provider cannot safely continue.
    Failed,
}

/// A typed, non-secret provider failure.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ProviderFailure {
    operation: ProviderOperation,
    kind: ProviderFailureKind,
}

impl ProviderFailure {
    /// Constructs a provider failure from closed categories only.
    #[must_use]
    pub const fn new(operation: ProviderOperation, kind: ProviderFailureKind) -> Self {
        Self { operation, kind }
    }

    /// Returns the failed operation category.
    #[must_use]
    pub const fn operation(self) -> ProviderOperation {
        self.operation
    }

    /// Returns the provider-independent failure class.
    #[must_use]
    pub const fn kind(self) -> ProviderFailureKind {
        self.kind
    }
}
