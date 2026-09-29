// Included inside the isolated Slot crate, not a shipped callback API.
struct TransformScratch<'a>(&'a mut [u8; 32]);
impl Drop for TransformScratch<'_> {
    fn drop(&mut self) {
        if !cfg!(probe_transform_skip_scratch_clear) {
            let _ = brynja_core::clear_owned_region(self.0);
        }
    }
}

impl Slot<'_> {
    /// Trusted operation seam only. Both source and candidate storage must
    /// already be admitted. No result bytes leave their exclusive storage.
    /// Every unsuccessful attempt on a ready value clears/quarantines it.
    /// Tokens are routing metadata; uniqueness is the adapter's responsibility.
    pub fn transform_secret(
        &mut self,
        token: [u64; 4],
        candidate: &mut [u8; 32],
        transform: impl FnOnce(&[u8; 32], &mut [u8; 32]) -> bool,
    ) -> Result<[u64; 4], Error> {
        let _ = brynja_core::clear_owned_region(candidate);
        let candidate = TransformScratch(candidate);
        let mut operation = self.consume()?;
        if !cfg!(probe_transform_ignore_token) && token != operation.slot.token() {
            return Err(Error::Rejected);
        }
        let Some(next) = operation.slot.generation.checked_add(1) else {
            return Err(Error::Exhausted);
        };
        if !transform(operation.slot.bytes, candidate.0) && !cfg!(probe_transform_ignore_failure) {
            return Err(Error::Fill);
        }
        if !cfg!(probe_transform_skip_commit) {
            operation.slot.bytes.copy_from_slice(candidate.0);
        }
        if !cfg!(probe_transform_reuse_generation) {
            operation.slot.generation = next;
        }
        let token = operation.slot.token();
        operation.success = Some(State::Ready);
        Ok(token)
    }
}
