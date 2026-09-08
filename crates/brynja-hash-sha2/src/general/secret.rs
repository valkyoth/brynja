use super::{Sha512TBits, Sha512TDigest, Sha512TError};
use crate::PublicDeclassification;
use brynja_core::{OwnedSecretRegion, SecretRegionInitialization};

/// Affine, parameter-bound secret digest. Drop clears the complete destination.
/// No Copy, Clone, formatting, equality, AsRef or Deref is implemented.
/// Caller-created copies and original inputs remain caller responsibilities.
pub struct Sha512TSecretDigest<'a> {
    parameter: Sha512TBits,
    region: OwnedSecretRegion<'a>,
}
impl<'a> Sha512TSecretDigest<'a> {
    pub(super) fn from_region(parameter: Sha512TBits, region: OwnedSecretRegion<'a>) -> Self {
        Self { parameter, region }
    }
    /// Exact public parameter; does not reveal secret bytes.
    #[must_use]
    pub const fn parameter(&self) -> Sha512TBits {
        self.parameter
    }
    /// Explicit borrowed exposure. Creating a copy makes its cleanup yours;
    /// this does not implicitly classify that copy as public.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.region.expose()
    }
    /// Deliberately releases a public copy and consumes/clears the secret owner.
    /// The returned public digest and its copies are no longer erased.
    pub fn declassify(
        self,
        _authority: PublicDeclassification,
    ) -> Result<Sha512TDigest, Sha512TError> {
        Sha512TDigest::computed(self.parameter, self.region.expose())
    }
}

// This guard is established before any fallible secret-output processing.
pub(super) fn begin(
    parameter: Sha512TBits,
    destination: &mut [u8],
) -> Result<SecretRegionInitialization<'_>, Sha512TError> {
    let length = destination.len();
    // Empty storage is already clear; preserve the public size error.
    if length == 0 {
        return Err(Sha512TError::OutputLength);
    }
    let guard = SecretRegionInitialization::begin(destination)?;
    if length != parameter.output_bytes() {
        return Err(Sha512TError::OutputLength);
    }
    Ok(guard)
}
