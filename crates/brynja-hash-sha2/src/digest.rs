/// One complete 256-bit SHA-256 digest.
///
/// A digest is public, non-secret output. Equality is ordinary value equality;
/// it is not a MAC verification or authentication operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct Sha256Digest([u8; Self::LENGTH]);

impl Sha256Digest {
    /// SHA-256 digest size in bytes.
    pub const LENGTH: usize = 32;

    /// Creates a digest value from exact bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Borrows the exact digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }

    /// Returns the exact digest bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; Self::LENGTH] {
        self.0
    }
}

impl AsRef<[u8]> for Sha256Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
