/// Trusted application-build policy, not metadata supplied by the candidate DLL.
///
/// Construct this only after reviewing the image's source/build/signature and
/// expected protocol. Store it as a static in the application, not an untrusted
/// runtime sidecar. The hash covers the complete final signed file. This is not
/// remote attestation or a claim of independent review.
#[cfg_attr(
    not(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")),
    allow(dead_code)
)]
pub struct ImagePolicy {
    pub(super) digest: [u8; 32],
    pub(super) family: [u8; 16],
    pub(super) image: [u8; 16],
    pub(super) version: u32,
    pub(super) security: u32,
    pub(super) minimum_import_security: [u32; 2],
}
impl ImagePolicy {
    /// Records the publisher's reviewed SHA-256 protocol image identity.
    /// Import floors are in ucrtbase_enclave/vertdll order. Zero explicitly
    /// disables that version floor; it does not establish OS patch currency.
    /// Invalid zero identities/versions reject when opening; no image is loaded
    /// by this constructor. Signature verification cannot be disabled here.
    pub const fn reviewed_sha256(
        digest: [u8; 32],
        family: [u8; 16],
        image: [u8; 16],
        version: u32,
        security: u32,
        minimum_import_security: [u32; 2],
    ) -> Self {
        Self {
            digest,
            family,
            image,
            version,
            security,
            minimum_import_security,
        }
    }
    #[cfg(any(
        test,
        all(
            target_os = "windows",
            target_arch = "x86_64",
            target_env = "msvc",
            not(miri),
            not(kani)
        )
    ))]
    pub(super) fn valid(&self) -> bool {
        self.digest != [0; 32]
            && self.family != [0; 16]
            && self.image != [0; 16]
            && self.version != 0
            && self.security != 0
    }
}
