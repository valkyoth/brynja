//! Secret-free provider failure classification.

/// One exact protocol-facing provider operation.
///
/// Seal/open, sign/verify, encapsulate/decapsulate, storage read/write, and
/// pending poll/cancel remain distinct capabilities. A provider may not use a
/// broader category to authorize the opposite direction or an implicit
/// fallback.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ProviderOperation {
    /// Compute a cryptographic hash.
    Hash,
    /// Compute or verify a message authentication code.
    Mac,
    /// Derive key material.
    KeyDerivation,
    /// Perform a key agreement.
    KeyAgreement,
    /// Produce a signature.
    Sign,
    /// Verify a signature.
    Verify,
    /// Encapsulate with a key-encapsulation mechanism.
    KemEncapsulate,
    /// Decapsulate with a key-encapsulation mechanism.
    KemDecapsulate,
    /// Seal plaintext with an AEAD.
    AeadSeal,
    /// Open ciphertext with an AEAD.
    AeadOpen,
    /// Obtain entropy bytes.
    Entropy,
    /// Read wall-clock time.
    WallClock,
    /// Read monotonic time.
    MonotonicClock,
    /// Perform a certificate-chain operation.
    CertificatePath,
    /// Read an external storage object.
    StorageRead,
    /// Write an external storage object.
    StorageWrite,
    /// Poll one pending provider operation.
    PendingPoll,
    /// Cancel one pending provider operation.
    PendingCancel,
}

impl ProviderOperation {
    /// Every operation in stable declaration order.
    pub const ALL: [Self; 18] = [
        Self::Hash,
        Self::Mac,
        Self::KeyDerivation,
        Self::KeyAgreement,
        Self::Sign,
        Self::Verify,
        Self::KemEncapsulate,
        Self::KemDecapsulate,
        Self::AeadSeal,
        Self::AeadOpen,
        Self::Entropy,
        Self::WallClock,
        Self::MonotonicClock,
        Self::CertificatePath,
        Self::StorageRead,
        Self::StorageWrite,
        Self::PendingPoll,
        Self::PendingCancel,
    ];

    pub(crate) const fn mask(self) -> u32 {
        match self {
            Self::Hash => 1,
            Self::Mac => 2,
            Self::KeyDerivation => 4,
            Self::KeyAgreement => 8,
            Self::Sign => 16,
            Self::Verify => 32,
            Self::KemEncapsulate => 64,
            Self::KemDecapsulate => 128,
            Self::AeadSeal => 256,
            Self::AeadOpen => 512,
            Self::Entropy => 1_024,
            Self::WallClock => 2_048,
            Self::MonotonicClock => 4_096,
            Self::CertificatePath => 8_192,
            Self::StorageRead => 16_384,
            Self::StorageWrite => 32_768,
            Self::PendingPoll => 65_536,
            Self::PendingCancel => 131_072,
        }
    }
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
