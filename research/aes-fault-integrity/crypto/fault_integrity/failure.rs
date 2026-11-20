//! Private failure labels for the unfinished fault-integrity workbench.
//! These are diagnostics, not fault-proof release decisions. Never expose
//! distinctions directly to an unauthenticated peer or treat them as proof
//! that a physical fault was observed.

use super::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProfileFailure {
    UnsupportedBuild,
    ImportRejected,
    DestinationAdmission,
    RejectedAndRetired,
    AlreadyRetired,
}

// Preserve the value-free error of the existing private fixtures. Future
// public owners need their own reviewed error API; ordinary AES is unchanged.
impl From<ProfileFailure> for Error {
    fn from(_: ProfileFailure) -> Self {
        Self::SecretMemory
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_private_diagnostic_maps_to_one_value_free_aes_error() {
        for diagnostic in [
            ProfileFailure::UnsupportedBuild,
            ProfileFailure::ImportRejected,
            ProfileFailure::DestinationAdmission,
            ProfileFailure::RejectedAndRetired,
            ProfileFailure::AlreadyRetired,
        ] {
            assert_eq!(Error::from(diagnostic), Error::SecretMemory);
        }
    }
}
