use brynja_core::{
    OwnedSecretRegion, SecretMemoryError, SecretRegionInitialization, clear_owned_region,
};

/// Explicit authority to classify one hardened digest as public output.
#[must_use = "public declassification must be consumed by finalization"]
pub struct PublicDeclassification {
    _private: (),
}

impl PublicDeclassification {
    /// Acknowledges that the digest is intentionally released as public data.
    pub const fn acknowledge() -> Self {
        Self { _private: () }
    }
}

/// Closed failure from a hardened SHA-2 operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HardenedSha2Error {
    /// The message would exceed the selected SHA-2 identity's length domain.
    MessageTooLong,
    /// The caller-owned output does not have the exact digest width.
    OutputLength,
    /// Mandatory typed secret ownership or clearing failed.
    SecretMemory,
}

impl From<SecretMemoryError> for HardenedSha2Error {
    fn from(_error: SecretMemoryError) -> Self {
        Self::SecretMemory
    }
}

pub(crate) fn write_public(
    source: &[u8],
    destination: &mut [u8],
    _authority: PublicDeclassification,
) -> Result<(), HardenedSha2Error> {
    if source.len() != destination.len() {
        return Err(HardenedSha2Error::OutputLength);
    }
    destination.copy_from_slice(source);
    Ok(())
}

pub(crate) fn write_secret<'output>(
    source: &[u8],
    destination: &'output mut [u8],
) -> Result<OwnedSecretRegion<'output>, HardenedSha2Error> {
    let destination_length = destination.len();
    let mut initialization = SecretRegionInitialization::begin(destination)?;
    if source.len() != destination_length {
        return Err(HardenedSha2Error::OutputLength);
    }
    initialization.write(source)?;
    initialization.finish().map_err(HardenedSha2Error::from)
}

pub(crate) fn clear_failed_secret_output(
    destination: &mut [u8],
    error: HardenedSha2Error,
) -> HardenedSha2Error {
    if !destination.is_empty() {
        let _ = clear_owned_region(destination);
    }
    error
}

#[cfg(kani)]
mod proofs {
    use super::{
        HardenedSha2Error, PublicDeclassification, clear_failed_secret_output, write_public,
    };

    #[kani::proof]
    fn public_length_failure_preserves_the_complete_destination() {
        let source: [u8; 3] = kani::any();
        let mut destination: [u8; 4] = kani::any();
        let before = destination;
        assert_eq!(
            write_public(
                &source,
                &mut destination,
                PublicDeclassification::acknowledge(),
            ),
            Err(HardenedSha2Error::OutputLength)
        );
        assert_eq!(destination, before);
    }

    #[kani::proof]
    fn secret_failure_clears_the_complete_destination() {
        let mut destination: [u8; 4] = kani::any();
        assert_eq!(
            clear_failed_secret_output(&mut destination, HardenedSha2Error::OutputLength),
            HardenedSha2Error::OutputLength
        );
        assert_eq!(destination, [0_u8; 4]);
    }
}
