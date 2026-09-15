//! Fixed clearing storage; no vector arrays outside the owner.
use super::Error;
use brynja_core::clear_owned_region;
use core::marker::PhantomData;

/// Exclusive, non-copying packed storage for one hardened permutation batch.
/// This owner is inert until borrowed by a session; no ordinary workspace import
/// exists. Drop erases all four regions, including inactive NEON capacity.
///
/// ```compile_fail
/// use brynja_crypto_cpu::keccak_hardened_batch::Workspace;
/// fn require<T: Send>() {}
/// require::<Workspace>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu::keccak_hardened_batch::Workspace;
/// fn require<T: Sync>() {}
/// require::<Workspace>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu::keccak_hardened_batch::Workspace;
/// fn require<T: Copy>() {}
/// require::<Workspace>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu::keccak_hardened_batch::Workspace;
/// fn require<T: Clone>() {}
/// require::<Workspace>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu::keccak_hardened_batch::Workspace;
/// fn require<T: core::fmt::Debug>() {}
/// require::<Workspace>();
/// ```
pub struct Workspace {
    pub(super) state: [[u8; 32]; 25],
    pub(super) columns: [[u8; 32]; 5],
    pub(super) deltas: [[u8; 32]; 5],
    pub(super) staging: [[u8; 32]; 25],
    thread_bound: PhantomData<*mut ()>,
}
impl Default for Workspace {
    fn default() -> Self {
        Self::new()
    }
}
impl Workspace {
    /// Constructs empty owned storage, with no caller secrets to move.
    pub const fn new() -> Self {
        Self {
            state: [[0; 32]; 25],
            columns: [[0; 32]; 5],
            deltas: [[0; 32]; 5],
            staging: [[0; 32]; 25],
            thread_bound: PhantomData,
        }
    }
    /// Clears all packed regions, including inactive capacity; does not erase callers.
    pub fn clear(&mut self) {
        self.wipe();
    }
    #[inline(never)]
    pub(super) fn wipe(&mut self) {
        let _ = clear_owned_region(self.state.as_flattened_mut());
        let _ = clear_owned_region(self.columns.as_flattened_mut());
        let _ = clear_owned_region(self.deltas.as_flattened_mut());
        let _ = clear_owned_region(self.staging.as_flattened_mut());
    }
    pub(super) fn pack(&mut self, states: &[[u64; 25]; 4], width: usize) -> Result<(), Error> {
        self.wipe();
        if width != 2 && width != 4 {
            return Err(Error::Invariant);
        }
        for (word, packed) in self.state.iter_mut().enumerate() {
            for (slot, state) in packed
                .as_chunks_mut::<8>()
                .0
                .iter_mut()
                .zip(states)
                .take(width)
            {
                slot.copy_from_slice(&state.get(word).ok_or(Error::Invariant)?.to_ne_bytes());
            }
        }
        Ok(())
    }
    pub(super) fn pack_bytes(
        &mut self,
        states: &[[u8; 200]; 4],
        width: usize,
    ) -> Result<(), Error> {
        self.wipe();
        if width != 2 && width != 4 {
            return Err(Error::Invariant);
        }
        for (word, packed) in self.state.iter_mut().enumerate() {
            for (slot, state) in packed
                .as_chunks_mut::<8>()
                .0
                .iter_mut()
                .zip(states)
                .take(width)
            {
                let bytes = state.as_chunks::<8>().0.get(word).ok_or(Error::Invariant)?;
                slot.copy_from_slice(&u64::from_le_bytes(*bytes).to_ne_bytes());
            }
        }
        Ok(())
    }
    // Equal-sized, bounded zips only: no fallible operation during commit.
    pub(super) fn commit(&self, states: &mut [[u64; 25]; 4], width: usize) {
        for (lane, state) in states.iter_mut().enumerate().take(width) {
            for (out, packed) in state.iter_mut().zip(&self.state) {
                for (index, bytes) in packed.as_chunks::<8>().0.iter().enumerate() {
                    if index == lane {
                        *out = u64::from_ne_bytes(*bytes);
                    }
                }
            }
        }
    }
    pub(super) fn commit_bytes(&self, states: &mut [[u8; 200]; 4], width: usize) {
        for (lane, state) in states.iter_mut().enumerate().take(width) {
            for (out, packed) in state.as_chunks_mut::<8>().0.iter_mut().zip(&self.state) {
                for (index, bytes) in packed.as_chunks::<8>().0.iter().enumerate() {
                    if index == lane {
                        out.copy_from_slice(&u64::from_ne_bytes(*bytes).to_le_bytes());
                    }
                }
            }
        }
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        self.wipe();
        #[cfg(test)]
        super::tests::observe_drop(self);
    }
}
