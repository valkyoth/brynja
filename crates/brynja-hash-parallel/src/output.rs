use brynja_hash_sha3::HardenedSha3SecretOutput;

/// Explicit authority to release hardened ParallelHash output as public.
#[must_use = "public declassification must be consumed by an output operation"]
pub struct ParallelHashPublicDeclassification {
    _private: (),
}

impl ParallelHashPublicDeclassification {
    /// Acknowledges that the selected ParallelHash bytes are public output.
    pub const fn acknowledge() -> Self {
        Self { _private: () }
    }
}

/// Typed ownership of hardened ParallelHash output.
///
/// Nonempty output is compiler-resistantly cleared when this owner is dropped.
#[must_use = "secret output must remain owned or be dropped for clearing"]
pub struct ParallelHashSecretOutput<'output> {
    inner: HardenedSha3SecretOutput<'output>,
}

impl<'output> ParallelHashSecretOutput<'output> {
    pub(crate) const fn new(inner: HardenedSha3SecretOutput<'output>) -> Self {
        Self { inner }
    }

    /// Borrows the completely initialized secret output.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.inner.expose()
    }
}
