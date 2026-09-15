use super::{CAPACITY, framing::Frame};
use crate::hardened::owner::HardenedFips202Owner;
use brynja_core::clear_owned_region;
use core::marker::PhantomData;
/// Distinct clearing state/scheduling owner. No ordinary batch workspace import.
/// All four lanes and inactive capacity clear on operation exit and Drop.
/// ```compile_fail
/// use brynja_hash_sha3::hardened_batch::Workspace;
/// fn require<T: Send>() {}
/// require::<Workspace>();
/// ```
/// ```compile_fail
/// use brynja_hash_sha3::hardened_batch::Workspace;
/// fn require<T: Sync>() {}
/// require::<Workspace>();
/// ```
/// ```compile_fail
/// use brynja_hash_sha3::hardened_batch::Workspace;
/// fn require<T: Copy>() {}
/// require::<Workspace>();
/// ```
/// ```compile_fail
/// use brynja_hash_sha3::hardened_batch::Workspace;
/// fn require<T: Clone>() {}
/// require::<Workspace>();
/// ```
/// ```compile_fail
/// use brynja_hash_sha3::hardened_batch::Workspace;
/// fn require<T: core::fmt::Debug>() {}
/// require::<Workspace>();
/// ```
pub struct Workspace {
    pub(super) states: [[u8; 200]; CAPACITY],
    pub(super) vector: [[u8; 200]; CAPACITY],
    pub(super) frames: [Frame; CAPACITY],
    pub(super) starts: [[u8; 8]; CAPACITY],
    pub(super) written: [[u8; 8]; CAPACITY],
    pub(super) ready: [u8; CAPACITY],
    pub(super) eligible: [u8; CAPACITY],
    pub(super) absorbing: [u8; CAPACITY],
    pub(super) scalar: HardenedFips202Owner<136>,
    pub(super) cpu: brynja_crypto_cpu::keccak_hardened_batch::Workspace,
    thread_bound: PhantomData<*mut ()>,
}
impl Default for Workspace {
    fn default() -> Self {
        Self::new()
    }
}
impl Workspace {
    /// Empty, bounded storage. No secret aggregate is moved into this owner.
    pub fn new() -> Self {
        Self {
            states: [[0; 200]; CAPACITY],
            vector: [[0; 200]; CAPACITY],
            frames: core::array::from_fn(|_| Frame::new()),
            starts: [[0; 8]; CAPACITY],
            written: [[0; 8]; CAPACITY],
            ready: [0; CAPACITY],
            eligible: [0; CAPACITY],
            absorbing: [0; CAPACITY],
            scalar: HardenedFips202Owner::new(),
            cpu: brynja_crypto_cpu::keccak_hardened_batch::Workspace::new(),
            thread_bound: PhantomData,
        }
    }
    /// Explicitly clear all regions; also performed on every operation exit.
    pub fn clear(&mut self) {
        self.wipe();
    }
    pub(super) fn wipe(&mut self) {
        let _ = clear_owned_region(self.states.as_flattened_mut());
        let _ = clear_owned_region(self.vector.as_flattened_mut());
        let _ = clear_owned_region(self.starts.as_flattened_mut());
        let _ = clear_owned_region(self.written.as_flattened_mut());
        let _ = clear_owned_region(&mut self.ready);
        let _ = clear_owned_region(&mut self.eligible);
        let _ = clear_owned_region(&mut self.absorbing);
        for frame in &mut self.frames {
            frame.wipe();
        }
        self.scalar.wipe();
        self.cpu.clear();
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        self.wipe();
        #[cfg(test)]
        super::tests::observe_drop(self);
    }
}
