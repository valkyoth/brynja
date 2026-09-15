//! Fixed clearing storage; no vector arrays outside the owner.
use super::Error;
use brynja_core::clear_owned_region;
use core::marker::PhantomData;

/// Exclusive, non-copying packed storage for one hardened compression batch.
/// This owner is inert until borrowed by a session; no ordinary workspace import
/// exists. Drop erases all four regions, including inactive NEON capacity.
///
/// ```compile_fail
/// use brynja_crypto_cpu::sha256_hardened_batch::Workspace;
/// fn require<T: Send>() {}
/// require::<Workspace>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu::sha256_hardened_batch::Workspace;
/// fn require<T: Sync>() {}
/// require::<Workspace>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu::sha256_hardened_batch::Workspace;
/// fn require<T: Copy>() {}
/// require::<Workspace>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu::sha256_hardened_batch::Workspace;
/// fn require<T: Clone>() {}
/// require::<Workspace>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu::sha256_hardened_batch::Workspace;
/// fn require<T: core::fmt::Debug>() {}
/// require::<Workspace>();
/// ```
pub struct Workspace {
    pub(super) initial: [[u8; 32]; 8],
    pub(super) schedule: [[u8; 32]; 64],
    pub(super) work: [[u8; 32]; 8],
    pub(super) temporary: [[u8; 32]; 6],
    thread_bound: PhantomData<*mut ()>,
}
impl Default for Workspace {
    fn default() -> Self {
        Self::new()
    }
}
impl Workspace {
    /// Explicitly clears all packed regions; also performed on operation exit
    /// and Drop. This does not revoke instruction authority or erase callers.
    pub fn clear(&mut self) {
        self.wipe();
    }
    pub(super) fn pack_bytes(
        &mut self,
        states: &[[u8; 32]; 8],
        blocks: &[[u8; 64]; 8],
        width: usize,
    ) -> Result<(), Error> {
        self.wipe();
        if width != 4 && width != 8 {
            return Err(Error::Invariant);
        }
        for (word, packed) in self.initial.iter_mut().enumerate() {
            for (slot, state) in packed
                .as_chunks_mut::<4>()
                .0
                .iter_mut()
                .zip(states)
                .take(width)
            {
                let bytes = state.as_chunks::<4>().0.get(word).ok_or(Error::Invariant)?;
                slot.copy_from_slice(&u32::from_be_bytes(*bytes).to_ne_bytes());
            }
        }
        for (word, packed) in self.schedule.iter_mut().take(16).enumerate() {
            for (slot, block) in packed
                .as_chunks_mut::<4>()
                .0
                .iter_mut()
                .zip(blocks)
                .take(width)
            {
                let bytes = block.as_chunks::<4>().0.get(word).ok_or(Error::Invariant)?;
                slot.copy_from_slice(&u32::from_be_bytes(*bytes).to_ne_bytes());
            }
        }
        Ok(())
    }
    pub(super) fn commit_bytes(&self, states: &mut [[u8; 32]; 8], width: usize) {
        for (lane, state) in states.iter_mut().enumerate().take(width) {
            for (out, packed) in state.as_chunks_mut::<4>().0.iter_mut().zip(&self.work) {
                for (index, bytes) in packed.as_chunks::<4>().0.iter().enumerate() {
                    if index == lane {
                        out.copy_from_slice(&u32::from_ne_bytes(*bytes).to_be_bytes());
                    }
                }
            }
        }
    }
    /// Constructs empty storage; contains no caller secrets during construction.
    pub const fn new() -> Self {
        Self {
            initial: [[0; 32]; 8],
            schedule: [[0; 32]; 64],
            work: [[0; 32]; 8],
            temporary: [[0; 32]; 6],
            thread_bound: PhantomData,
        }
    }
    #[inline(never)]
    pub(super) fn wipe(&mut self) {
        let _ = clear_owned_region(self.initial.as_flattened_mut());
        let _ = clear_owned_region(self.schedule.as_flattened_mut());
        let _ = clear_owned_region(self.work.as_flattened_mut());
        let _ = clear_owned_region(self.temporary.as_flattened_mut());
    }
    pub(super) fn pack(
        &mut self,
        states: &[[u32; 8]; 8],
        blocks: &[[u8; 64]; 8],
        width: usize,
    ) -> Result<(), Error> {
        self.wipe();
        if width != 4 && width != 8 {
            return Err(Error::Invariant);
        }
        for (word, packed) in self.initial.iter_mut().enumerate() {
            for (slot, state) in packed
                .as_chunks_mut::<4>()
                .0
                .iter_mut()
                .zip(states)
                .take(width)
            {
                slot.copy_from_slice(&state.get(word).ok_or(Error::Invariant)?.to_ne_bytes());
            }
        }
        for (word, packed) in self.schedule.iter_mut().take(16).enumerate() {
            for (slot, block) in packed
                .as_chunks_mut::<4>()
                .0
                .iter_mut()
                .zip(blocks)
                .take(width)
            {
                let bytes = block.as_chunks::<4>().0.get(word).ok_or(Error::Invariant)?;
                slot.copy_from_slice(&u32::from_be_bytes(*bytes).to_ne_bytes());
            }
        }
        Ok(())
    }
    // Fixed equal-size zips; no fallible operations after output commit begins.
    pub(super) fn commit(&self, states: &mut [[u32; 8]; 8], width: usize) {
        for (lane, state) in states.iter_mut().enumerate().take(width) {
            for (out, packed) in state.iter_mut().zip(&self.work) {
                // Iteration over the same fixed eight slots makes this total.
                for (index, bytes) in packed.as_chunks::<4>().0.iter().enumerate() {
                    if index == lane {
                        *out = u32::from_ne_bytes(*bytes);
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
