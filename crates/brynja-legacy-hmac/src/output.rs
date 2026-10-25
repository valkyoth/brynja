use crate::Algorithm;
use brynja_core::{Choice, OwnedSecretRegion};
use core::marker::PhantomData;

/// Intentionally public legacy authenticator, bound to its algorithm identity.
#[must_use = "consume the authenticator"]
pub struct Tag<'a, A: Algorithm> {
    bytes: &'a [u8],
    algorithm: PhantomData<A>,
}
impl<'a, A: Algorithm> Tag<'a, A> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            algorithm: PhantomData,
        }
    }
    /// Borrows the declassified bytes for a legacy transport.
    pub const fn as_bytes(&self) -> &[u8] {
        self.bytes
    }
    #[cfg(feature = "sha1-execution")]
    pub(crate) fn rebind<B: Algorithm>(self) -> Tag<'a, B> {
        Tag::new(self.bytes)
    }
}

/// Local clearing ownership of a secret legacy authenticator.
///
/// ```compile_fail
/// fn send<T: Send>() {}
/// send::<brynja_legacy_hmac::SecretTag<'static, brynja_legacy_hmac::Sha1>>();
/// ```
/// ```compile_fail
/// fn sync<T: Sync>() {}
/// sync::<brynja_legacy_hmac::SecretTag<'static, brynja_legacy_hmac::Md5>>();
/// ```
/// ```compile_fail
/// fn copy<T: Copy>() {}
/// copy::<brynja_legacy_hmac::SecretTag<'static, brynja_legacy_hmac::Sha1>>();
/// ```
/// ```compile_fail
/// fn clone<T: Clone>() {}
/// clone::<brynja_legacy_hmac::SecretTag<'static, brynja_legacy_hmac::Md5>>();
/// ```
/// ```compile_fail
/// fn debug<T: core::fmt::Debug>() {}
/// debug::<brynja_legacy_hmac::SecretTag<'static, brynja_legacy_hmac::Sha1>>();
/// ```
#[must_use = "retain the clearing owner until the secret is no longer needed"]
pub struct SecretTag<'a, A: Algorithm> {
    region: OwnedSecretRegion<'a>,
    local: PhantomData<(*mut (), A)>,
}
impl<'a, A: Algorithm> SecretTag<'a, A> {
    pub(crate) const fn new(region: OwnedSecretRegion<'a>) -> Self {
        Self {
            region,
            local: PhantomData,
        }
    }
    /// Borrows secret bytes; caller-created copies require their own cleanup.
    pub fn expose(&self) -> &[u8] {
        self.region.expose()
    }
    #[cfg(feature = "sha1-execution")]
    pub(crate) fn rebind<B: Algorithm>(self) -> SecretTag<'a, B> {
        SecretTag::new(self.region)
    }
}

/// Explicit final verification decision, not a digest or modern tag.
#[must_use = "the authentication decision must be checked"]
pub struct Verification(Choice);
impl Verification {
    pub(crate) const fn new(choice: Choice) -> Self {
        Self(choice)
    }
    /// Declassifies only the final authentication decision.
    pub const fn expose_public(self) -> bool {
        self.0.expose_public()
    }
    #[inline(always)]
    pub(crate) fn require_match(self) -> Result<(), crate::VerificationError> {
        if self.expose_public() {
            Ok(())
        } else {
            Err(crate::VerificationError::Mismatch(()))
        }
    }
}
