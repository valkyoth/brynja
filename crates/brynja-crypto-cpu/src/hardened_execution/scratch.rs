use brynja_core::clear_owned_region;

/// Source-owned schedule and vector staging. Registers/spills are residuals.
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

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub(crate) fn expand32(&mut self, block: &[u8; 128]) {
        self.schedule[..64].copy_from_slice(&block[..64]);
        for i in 16_usize..64 {
            let x = read32(&self.schedule, i.saturating_sub(15));
            let y = read32(&self.schedule, i.saturating_sub(2));
            let value = read32(&self.schedule, i.saturating_sub(16))
                .wrapping_add(x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3))
                .wrapping_add(read32(&self.schedule, i.saturating_sub(7)))
                .wrapping_add(y.rotate_right(17) ^ y.rotate_right(19) ^ (y >> 10));
            write32(&mut self.schedule, i, value);
        }
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn expand64(&mut self, block: &[u8; 128]) {
        self.schedule[..128].copy_from_slice(block);
        for i in 16_usize..80 {
            let x = read64(&self.schedule, i.saturating_sub(15));
            let y = read64(&self.schedule, i.saturating_sub(2));
            let value = read64(&self.schedule, i.saturating_sub(16))
                .wrapping_add(x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7))
                .wrapping_add(read64(&self.schedule, i.saturating_sub(7)))
                .wrapping_add(y.rotate_right(19) ^ y.rotate_right(61) ^ (y >> 6));
            write64(&mut self.schedule, i, value);
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        self.wipe();
    }
}

// All offsets are private fixed round/state indices, never caller-selected.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) fn read32(bytes: &[u8], index: usize) -> u32 {
    bytes
        .as_chunks::<4>()
        .0
        .get(index)
        .copied()
        .map(u32::from_be_bytes)
        .unwrap_or(0)
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) fn write32(bytes: &mut [u8], index: usize, value: u32) {
    if let Some(word) = bytes.as_chunks_mut::<4>().0.get_mut(index) {
        *word = value.to_be_bytes();
    }
}
#[cfg(target_arch = "aarch64")]
pub(crate) fn read64(bytes: &[u8], index: usize) -> u64 {
    bytes
        .as_chunks::<8>()
        .0
        .get(index)
        .copied()
        .map(u64::from_be_bytes)
        .unwrap_or(0)
}
#[cfg(target_arch = "aarch64")]
pub(crate) fn write64(bytes: &mut [u8], index: usize, value: u64) {
    if let Some(word) = bytes.as_chunks_mut::<8>().0.get_mut(index) {
        *word = value.to_be_bytes();
    }
}
