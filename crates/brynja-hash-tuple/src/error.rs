/// Closed failure from a TupleHash operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TupleHashError {
    /// A bit string or output descriptor was not canonical.
    InvalidBitString,
    /// The encoded input or tuple-item counter cannot be represented.
    MessageTooLong,
    /// The requested output length cannot be represented.
    OutputTooLong,
    /// A streamed item ended before its declared bit length was consumed.
    IncompleteItem,
    /// An abandoned incomplete item permanently closed the parent state.
    ItemAbandoned,
    /// Mandatory typed secret ownership or clearing failed.
    SecretMemory,
    /// The underlying state was already consumed.
    StateConsumed,
}

impl From<brynja_hash_sha3::HardenedSha3Error> for TupleHashError {
    fn from(error: brynja_hash_sha3::HardenedSha3Error) -> Self {
        use brynja_hash_sha3::HardenedSha3Error;
        match error {
            HardenedSha3Error::StateConsumed => Self::StateConsumed,
            HardenedSha3Error::MessageTooLong => Self::MessageTooLong,
            HardenedSha3Error::OutputTooLong | HardenedSha3Error::OutputLength => {
                Self::OutputTooLong
            }
            HardenedSha3Error::SecretMemory => Self::SecretMemory,
            _ => Self::StateConsumed,
        }
    }
}
