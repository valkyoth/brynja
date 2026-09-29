// Included in the existing checked in-page placement crate.
impl Placed<'_> {
    pub fn rehash(
        &mut self,
        token: [u64; 4],
        workspace: &mut Sha256Workspace,
        candidate: &mut [u8; 32],
        staging: &mut [u8; 32],
    ) -> Result<[u64; 4], Error> {
        self.owner().rehash(token, workspace, candidate, staging)
    }
}
