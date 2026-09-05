use brynja_core::{OwnedSecretRegion, SecretRegionInitialization, clear_owned_region};

/// Failure of a SHA-1 operation; no diagnostic contains input or secret state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Sha1Error {
    /// Message length would reach or exceed 2^64 bits.
    MessageTooLong,
    /// Output must have exactly 20 bytes.
    OutputLength,
    /// Typed secret initialization failed.
    SecretMemory,
}

impl core::fmt::Display for Sha1Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::MessageTooLong => "SHA-1 message length exceeds its bit domain",
            Self::OutputLength => "SHA-1 output must be exactly 20 bytes",
            Self::SecretMemory => "SHA-1 secret output initialization failed",
        })
    }
}

impl core::error::Error for Sha1Error {}

/// Explicit authority to release one hardened digest as public data.
#[must_use]
pub struct PublicDeclassification {
    _private: (),
}

impl PublicDeclassification {
    /// Acknowledges intentional public release; not a cryptographic admission.
    pub const fn acknowledge() -> Self {
        Self { _private: () }
    }
}

pub(crate) fn failed(destination: &mut [u8], error: Sha1Error) -> Sha1Error {
    if !destination.is_empty() {
        let _ = clear_owned_region(destination);
    }
    error
}

pub(crate) fn secret<'out>(
    source: &[u8; 20],
    destination: &'out mut [u8],
) -> Result<OwnedSecretRegion<'out>, Sha1Error> {
    let mut initialization =
        SecretRegionInitialization::begin(destination).map_err(|_| Sha1Error::SecretMemory)?;
    initialization
        .write(source)
        .map_err(|_| Sha1Error::SecretMemory)?;
    initialization.finish().map_err(|_| Sha1Error::SecretMemory)
}
