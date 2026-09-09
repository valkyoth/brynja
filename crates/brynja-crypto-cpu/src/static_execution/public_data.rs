//! Explicit call-site classification for non-erasing raw execution.

/// Caller attestation that a value contains only public, non-secret-derived data.
///
/// This marker makes classification visible; it cannot inspect bytes or prove
/// their provenance. It is not a hardened owner, declassification mechanism,
/// CPU permit, or promise of memory erasure. Never wrap keys, passwords, HMAC/KDF
/// intermediates or other confidential material. Use a hardened API instead.
///
/// Raw execution borrows through this marker, avoiding another owned state copy.
/// There are no implicit conversions from raw buffers or hardened owners.
pub struct PublicData<T>(T);

impl<T> PublicData<T> {
    /// Explicitly asserts that `value` is public and not derived from secrets.
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Returns the classified value without copying its contents.
    pub fn into_inner(self) -> T {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::PublicData;

    #[test]
    fn public_borrows_preserve_identity_and_mutability() {
        let mut bytes = [1, 2, 3];
        let classified = PublicData::new(&mut bytes);
        classified.into_inner()[1] = 7;
        assert_eq!(PublicData::new(&bytes).into_inner(), &[1, 7, 3]);
    }
}
