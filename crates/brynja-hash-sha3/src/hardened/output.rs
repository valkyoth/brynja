use brynja_core::{OwnedSecretRegion, SecretMemoryError, SecretRegionInitialization};

/// Explicit authority to release hardened SHA-3 or SHAKE output as public.
#[must_use = "public declassification must be consumed by an output operation"]
pub struct Sha3PublicDeclassification {
    _private: (),
}

impl Sha3PublicDeclassification {
    /// Acknowledges that the selected digest or XOF bytes are public output.
    pub const fn acknowledge() -> Self {
        Self { _private: () }
    }
}

/// Typed ownership of one hardened SHA-3/SHAKE secret output.
///
/// Empty XOF output is represented without a memory region. Nonempty output
/// owns the complete caller destination and clears it on `Drop`.
#[must_use = "secret output must remain owned or be dropped for clearing"]
pub struct HardenedSha3SecretOutput<'output> {
    region: Option<OwnedSecretRegion<'output>>,
}

impl<'output> HardenedSha3SecretOutput<'output> {
    pub(crate) const fn empty() -> Self {
        Self { region: None }
    }

    pub(crate) const fn from_region(region: OwnedSecretRegion<'output>) -> Self {
        Self {
            region: Some(region),
        }
    }

    /// Borrows the completely initialized secret output.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        match self.region.as_ref() {
            Some(region) => region.expose(),
            None => &[],
        }
    }
}

/// Closed failure from one hardened FIPS 202 operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HardenedSha3Error {
    /// The construction owner was irreversibly finalized or explicitly wiped.
    StateConsumed,
    /// The message counter would be exhausted.
    MessageTooLong,
    /// The output counter would be exhausted.
    OutputTooLong,
    /// The fixed-output destination has the wrong length.
    OutputLength,
    /// Mandatory typed secret ownership or clearing failed.
    SecretMemory,
}

impl From<SecretMemoryError> for HardenedSha3Error {
    fn from(_error: SecretMemoryError) -> Self {
        Self::SecretMemory
    }
}

pub(crate) fn begin_secret(
    destination: &mut [u8],
) -> Result<Option<SecretRegionInitialization<'_>>, HardenedSha3Error> {
    if destination.is_empty() {
        return Ok(None);
    }
    SecretRegionInitialization::begin(destination)
        .map(Some)
        .map_err(HardenedSha3Error::from)
}

pub(crate) fn finish_secret<'output>(
    initialization: Option<SecretRegionInitialization<'output>>,
) -> Result<HardenedSha3SecretOutput<'output>, HardenedSha3Error> {
    match initialization {
        Some(initialization) => initialization
            .finish()
            .map(HardenedSha3SecretOutput::from_region)
            .map_err(HardenedSha3Error::from),
        None => Ok(HardenedSha3SecretOutput::empty()),
    }
}
