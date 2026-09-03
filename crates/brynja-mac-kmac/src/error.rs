use brynja_hash_sha3::HardenedSha3Error;

/// Closed failure from a KMAC or KMACXOF operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KmacError {
    /// The production constructor requires a key at least as long as the
    /// selected KMAC security strength.
    KeyTooShort,
    /// A production tag operation requires the full selected security strength.
    TagTooShort,
    /// The message or an encoded input length cannot be represented.
    MessageTooLong,
    /// The requested output length cannot be represented.
    OutputTooLong,
    /// Mandatory typed secret ownership or clearing failed.
    SecretMemory,
    /// A canonical arbitrary-bit shape could not be constructed.
    InvalidBitString,
}

impl From<HardenedSha3Error> for KmacError {
    fn from(error: HardenedSha3Error) -> Self {
        match error {
            HardenedSha3Error::MessageTooLong => Self::MessageTooLong,
            HardenedSha3Error::OutputTooLong | HardenedSha3Error::OutputLength => {
                Self::OutputTooLong
            }
            HardenedSha3Error::SecretMemory => Self::SecretMemory,
            _ => Self::SecretMemory,
        }
    }
}
