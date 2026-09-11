use brynja_hash_sha3::HardenedSha3Error;

/// Closed failure from a KMAC or KMACXOF operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KmacError {
    /// The embedded hardened construction was irreversibly finalized or wiped.
    StateConsumed,
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
    /// A required hardened execution capability was not supplied.
    #[cfg(feature = "hardened-execution")]
    AccelerationUnavailable,
    /// The selected hardened backend failed; never permits fallback.
    #[cfg(feature = "hardened-execution")]
    Execution(brynja_hash_sha3::hardened_execution::Error),
}

#[cfg(feature = "hardened-execution")]
impl From<brynja_hash_sha3::hardened_execution::Error> for KmacError {
    fn from(error: brynja_hash_sha3::hardened_execution::Error) -> Self {
        Self::Execution(error)
    }
}

impl From<HardenedSha3Error> for KmacError {
    fn from(error: HardenedSha3Error) -> Self {
        match error {
            HardenedSha3Error::StateConsumed => Self::StateConsumed,
            HardenedSha3Error::MessageTooLong => Self::MessageTooLong,
            HardenedSha3Error::OutputTooLong | HardenedSha3Error::OutputLength => {
                Self::OutputTooLong
            }
            HardenedSha3Error::SecretMemory => Self::SecretMemory,
            _ => Self::SecretMemory,
        }
    }
}
