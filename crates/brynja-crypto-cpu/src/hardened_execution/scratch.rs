use brynja_core::clear_owned_region;

/// Source-owned SHA-2 schedule and vector staging. Kernel register cleanup is
/// a separate boundary; this owner also clears on errors and recoverable unwind.
#[repr(C, align(16))]
pub(crate) struct Scratch {
    pub(crate) schedule: [u8; 640],
    pub(crate) vectors: [u8; 64],
}

impl Scratch {
    pub(crate) const fn new() -> Self {
        Self {
            schedule: [0; 640],
            vectors: [0; 64],
        }
    }

    #[inline(never)]
    pub(crate) fn wipe(&mut self) {
        let _ = clear_owned_region(&mut self.schedule);
        let _ = clear_owned_region(&mut self.vectors);
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        self.wipe();
    }
}
