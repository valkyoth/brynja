/// Closed failure from a ParallelHash operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ParallelHashError {
    /// The caller supplied an empty sequential workspace or zero block size.
    InvalidBlockSize,
    /// A bit string or output descriptor was not canonical.
    InvalidBitString,
    /// The encoded input or leaf counter cannot be represented.
    MessageTooLong,
    /// The requested output length cannot be represented.
    OutputTooLong,
    /// A scheduled leaf index was absent or did not match the merge position.
    LeafOrder,
    /// A leaf result was produced for a different block size or leaf count.
    LeafIdentity,
    /// Mandatory typed secret ownership or clearing failed.
    SecretMemory,
    /// The underlying state was already consumed or permanently failed.
    StateConsumed,
}

impl From<brynja_hash_sha3::HardenedSha3Error> for ParallelHashError {
    fn from(error: brynja_hash_sha3::HardenedSha3Error) -> Self {
        use brynja_hash_sha3::HardenedSha3Error;
        match error {
            HardenedSha3Error::MessageTooLong => Self::MessageTooLong,
            HardenedSha3Error::OutputTooLong | HardenedSha3Error::OutputLength => {
                Self::OutputTooLong
            }
            HardenedSha3Error::SecretMemory => Self::SecretMemory,
            _ => Self::StateConsumed,
        }
    }
}
