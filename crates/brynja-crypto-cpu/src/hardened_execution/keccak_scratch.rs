use brynja_core::clear_owned_region;

/// Seven exact owned regions. Kernel register cleanup is a separate boundary;
/// this owner also clears all regions on errors and recoverable unwind.
#[repr(C, align(32))]
pub(crate) struct KeccakScratch {
    pub(crate) lanes: [u8; 200],
    pub(crate) columns: [u8; 40],
    pub(crate) theta: [u8; 40],
    pub(crate) rearranged: [u8; 200],
    pub(crate) current: [u8; 32],
    pub(crate) next: [u8; 32],
    pub(crate) following: [u8; 32],
}

impl KeccakScratch {
    pub(crate) const fn new() -> Self {
        Self {
            lanes: [0; 200],
            columns: [0; 40],
            theta: [0; 40],
            rearranged: [0; 200],
            current: [0; 32],
            next: [0; 32],
            following: [0; 32],
        }
    }

    #[inline(never)]
    pub(crate) fn wipe(&mut self) {
        let _ = clear_owned_region(&mut self.lanes);
        let _ = clear_owned_region(&mut self.columns);
        let _ = clear_owned_region(&mut self.theta);
        let _ = clear_owned_region(&mut self.rearranged);
        let _ = clear_owned_region(&mut self.current);
        let _ = clear_owned_region(&mut self.next);
        let _ = clear_owned_region(&mut self.following);
    }
}

impl Drop for KeccakScratch {
    fn drop(&mut self) {
        self.wipe();
    }
}
