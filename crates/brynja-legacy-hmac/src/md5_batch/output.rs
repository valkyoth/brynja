use brynja_core::OwnedSecretRegion;
use core::marker::PhantomData;

/// Intentionally declassified legacy HMAC-MD5 tags with their active-slot map.
#[must_use = "consume the authenticators"]
pub struct Tags<'a> {
    bytes: &'a [[u8; 16]; 8],
    active: [bool; 8],
    length: usize,
}
impl<'a> Tags<'a> {
    pub(super) const fn new(bytes: &'a [[u8; 16]; 8], active: [bool; 8], length: usize) -> Self {
        Self {
            bytes,
            active,
            length,
        }
    }
    /// Returns the selected truncation for an active slot; inactive/invalid slots
    /// return None. The active-slot map is public input metadata.
    pub fn get(&self, lane: usize) -> Option<&[u8]> {
        if !self.active.get(lane).copied().unwrap_or(false) {
            return None;
        }
        self.bytes.get(lane)?.get(..self.length)
    }
}

/// Affine, local clearing ownership of all eight secret HMAC-MD5 output slots.
/// Caller-created copies remain caller-owned; forgetting the owner defeats Drop.
/// ```compile_fail
/// fn send<T: Send>() {}
/// send::<brynja_legacy_hmac::md5_batch::SecretTags<'static>>();
/// ```
/// ```compile_fail
/// fn clone<T: Clone>() {}
/// clone::<brynja_legacy_hmac::md5_batch::SecretTags<'static>>();
/// ```
#[must_use = "retain the clearing owner until the secrets are no longer needed"]
pub struct SecretTags<'a> {
    region: OwnedSecretRegion<'a>,
    active: [bool; 8],
    length: usize,
    local: PhantomData<*mut ()>,
}
impl<'a> SecretTags<'a> {
    pub(super) const fn new(
        region: OwnedSecretRegion<'a>,
        active: [bool; 8],
        length: usize,
    ) -> Self {
        Self {
            region,
            active,
            length,
            local: PhantomData,
        }
    }
    /// Borrows one active secret tag without creating an ordinary output owner.
    pub fn expose(&self, lane: usize) -> Option<&[u8]> {
        if !self.active.get(lane).copied().unwrap_or(false) {
            return None;
        }
        let start = lane.checked_mul(16)?;
        self.region
            .expose()
            .get(start..start.checked_add(self.length)?)
    }
}
