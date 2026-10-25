//! Independent typed constructor/Result layout probes, never executed on secrets.
use brynja_core::OwnedSecretRegion;

macro_rules! probes {
    ($module:ident, $hash:path, $error:path) => {
        pub mod $module {
            use super::OwnedSecretRegion;
            use $error as HashError;
            use $hash as Hash;

            #[inline(never)]
            pub fn initial() -> Hash {
                Hash::new()
            }

            #[inline(never)]
            pub fn accepted(
                owner: OwnedSecretRegion<'_>,
            ) -> Result<OwnedSecretRegion<'_>, HashError> {
                Ok(owner)
            }

            #[inline(never)]
            pub fn rejected() -> Result<OwnedSecretRegion<'static>, HashError> {
                Err(HashError::OutputLength)
            }
        }
    };
}

probes!(
    sha1,
    brynja_legacy_sha1::HardenedSha1,
    brynja_legacy_sha1::Sha1Error
);
probes!(
    md5,
    brynja_legacy_md5::HardenedMd5,
    brynja_legacy_md5::Md5Error
);
