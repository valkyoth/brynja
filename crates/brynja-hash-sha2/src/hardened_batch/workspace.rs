use super::{CAPACITY, Error};
use crate::hardened::HardenedSha2Owner;
use brynja_core::clear_owned_region;

/// Reusable clearing lane, block, metadata, scalar and SIMD storage.
/// Secret data is introduced only through exclusive operation borrows; no
/// ordinary workspace conversion exists. Inactive capacity clears too.
///
/// ```compile_fail
/// use brynja_hash_sha2::hardened_batch::Workspace;
/// fn require<T: Send>() {}
/// require::<Workspace>();
/// ```
///
/// ```compile_fail
/// use brynja_hash_sha2::hardened_batch::Workspace;
/// fn require<T: Sync>() {}
/// require::<Workspace>();
/// ```
///
/// ```compile_fail
/// use brynja_hash_sha2::hardened_batch::Workspace;
/// fn require<T: Copy>() {}
/// require::<Workspace>();
/// ```
///
/// ```compile_fail
/// use brynja_hash_sha2::hardened_batch::Workspace;
/// fn require<T: Clone>() {}
/// require::<Workspace>();
/// ```
///
/// ```compile_fail
/// use brynja_hash_sha2::hardened_batch::Workspace;
/// fn require<T: core::fmt::Debug>() {}
/// require::<Workspace>();
/// ```
pub struct Workspace {
    pub(super) states: [[u8; 32]; CAPACITY],
    pub(super) packed: [[u8; 32]; CAPACITY],
    pub(super) blocks: [[u8; 64]; CAPACITY],
    pub(super) output: [[u8; 32]; CAPACITY],
    pub(super) offsets: [[u8; 8]; CAPACITY],
    pub(super) indices: [u8; CAPACITY],
    pub(super) active: [u8; 1],
    pub(super) scalar: HardenedSha2Owner,
    pub(super) cpu: brynja_crypto_cpu::sha256_hardened_batch::Workspace,
}
impl Default for Workspace {
    fn default() -> Self {
        Self::new()
    }
}
impl Workspace {
    /// Allocates fixed stack/caller storage; no secret-derived construction move.
    pub fn new() -> Self {
        Self {
            states: [[0; 32]; CAPACITY],
            packed: [[0; 32]; CAPACITY],
            blocks: [[0; 64]; CAPACITY],
            output: [[0; 32]; CAPACITY],
            offsets: [[0; 8]; CAPACITY],
            indices: [0; CAPACITY],
            active: [0],
            scalar: HardenedSha2Owner::new32([0; 8]),
            cpu: brynja_crypto_cpu::sha256_hardened_batch::Workspace::new(),
        }
    }
    #[inline(never)]
    pub(super) fn wipe(&mut self) {
        let _ = clear_owned_region(self.states.as_flattened_mut());
        let _ = clear_owned_region(self.packed.as_flattened_mut());
        let _ = clear_owned_region(self.blocks.as_flattened_mut());
        let _ = clear_owned_region(self.output.as_flattened_mut());
        let _ = clear_owned_region(self.offsets.as_flattened_mut());
        let _ = clear_owned_region(&mut self.indices);
        let _ = clear_owned_region(&mut self.active);
        self.scalar.wipe();
        // The CPU operation guard clears its workspace on every exit; this
        // public clearing method additionally covers idle workspace teardown.
        self.cpu.clear();
    }
    pub(super) fn index(&self, group: usize, lane: usize) -> Result<usize, Error> {
        let position = group.checked_add(lane).ok_or(Error::Invariant)?;
        self.indices
            .get(position)
            .copied()
            .map(usize::from)
            .ok_or(Error::Invariant)
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        self.wipe();
        #[cfg(test)]
        super::tests::observe_drop(self);
    }
}
