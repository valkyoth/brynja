use brynja_core::{OwnedSecretRegion, SecretRegionInitialization, clear_owned_region};

/// Failure of a MD5 operation; no diagnostic contains input or secret state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Md5Error {
    /// Message length would reach or exceed 2^128 bits.
    MessageTooLong,
    /// Output must have exactly 16 bytes.
    OutputLength,
    /// Typed secret initialization failed.
    SecretMemory,
}

impl core::fmt::Display for Md5Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::MessageTooLong => "MD5 message length exceeds its bit domain",
            Self::OutputLength => "MD5 output must be exactly 16 bytes",
            Self::SecretMemory => "MD5 secret output initialization failed",
        })
    }
}

impl core::error::Error for Md5Error {}

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

pub(crate) fn failed(destination: &mut [u8], error: Md5Error) -> Md5Error {
    if !destination.is_empty() {
        let _ = clear_owned_region(destination);
    }
    error
}

pub(crate) fn secret<'out>(
    source: &[u8; 16],
    destination: &'out mut [u8],
) -> Result<OwnedSecretRegion<'out>, Md5Error> {
    let mut initialization =
        SecretRegionInitialization::begin(destination).map_err(|_| Md5Error::SecretMemory)?;
    initialization
        .write(source)
        .map_err(|_| Md5Error::SecretMemory)?;
    initialization.finish().map_err(|_| Md5Error::SecretMemory)
}
