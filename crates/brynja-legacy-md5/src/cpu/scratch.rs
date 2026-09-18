//! All source-owned packed SIMD storage, including unused NEON half-lanes.
use brynja_core::clear_owned_region;

#[repr(C)]
pub(crate) struct Scratch {
    pub(crate) initial: [[u8; 32]; 4],
    pub(crate) words: [[u8; 32]; 16],
    pub(crate) work: [[u8; 32]; 4],
    pub(crate) temporary: [[u8; 32]; 3],
}
impl Scratch {
    pub(crate) const fn new() -> Self {
        Self {
            initial: [[0; 32]; 4],
            words: [[0; 32]; 16],
            work: [[0; 32]; 4],
            temporary: [[0; 32]; 3],
        }
    }
    #[inline(never)]
    pub(crate) fn wipe(&mut self) {
        let _ = clear_owned_region(self.initial.as_flattened_mut());
        let _ = clear_owned_region(self.words.as_flattened_mut());
        let _ = clear_owned_region(self.work.as_flattened_mut());
        let _ = clear_owned_region(self.temporary.as_flattened_mut());
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clears_all_packed_regions_including_inactive_storage() {
        let mut scratch = Scratch::new();
        scratch.initial.as_flattened_mut().fill(0xa5);
        scratch.words.as_flattened_mut().fill(0xa5);
        scratch.work.as_flattened_mut().fill(0xa5);
        scratch.temporary.as_flattened_mut().fill(0xa5);
        scratch.wipe();
        assert_eq!(scratch.initial, [[0; 32]; 4]);
        assert_eq!(scratch.words, [[0; 32]; 16]);
        assert_eq!(scratch.work, [[0; 32]; 4]);
        assert_eq!(scratch.temporary, [[0; 32]; 3]);
    }
}
