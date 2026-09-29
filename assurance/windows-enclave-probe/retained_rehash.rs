// Included inside the isolated retained-digest crate; safe Rust only.
impl Owner<'_> {
    /// Fixed secret-to-secret SHA-256 operation. The input is the retained
    /// 32-byte digest, not its hexadecimal encoding. This adds no public output.
    /// Scratch and workspace admission remain the native adapter's obligation.
    pub fn rehash(
        &mut self,
        token: [u64; 4],
        workspace: &mut Sha256Workspace,
        candidate: &mut [u8; 32],
        staging: &mut [u8; 32],
    ) -> Result<[u64; 4], Error> {
        // Initialize public IV state before admission, never mask post-work
        // cleanup with an extra workspace wipe after the operation.
        workspace.with(|state| state.cancel());
        let _ = clear_owned_region(staging);
        let staging = Staging(staging);
        self.slot
            .transform_secret(token, candidate, |input, destination| {
                workspace
                    .with(|mut state| {
                        state.update(input)?;
                        let secret = state.finalize_secret(staging.0)?;
                        destination.copy_from_slice(secret.expose());
                        Ok::<(), brynja_hash_sha2::HardenedSha2Error>(())
                    })
                    .is_ok()
            })
    }
}
