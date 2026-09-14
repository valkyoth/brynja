//! All source-owned packed SIMD storage, including unused NEON half-lanes.
use brynja_core::clear_owned_region;

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

#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_endian = "little")
))]
pub(super) fn round(round: usize) -> Result<(usize, i32), super::Md5BackendError> {
    let (index, shifts) = match round {
        0..=15 => (round, [7, 12, 17, 22]),
        16..=31 => (
            round.saturating_mul(5).saturating_add(1) % 16,
            [5, 9, 14, 20],
        ),
        32..=47 => (
            round.saturating_mul(3).saturating_add(5) % 16,
            [4, 11, 16, 23],
        ),
        48..=63 => (round.saturating_mul(7) % 16, [6, 10, 15, 21]),
        _ => return Err(super::Md5BackendError::Quarantined),
    };
    let shift = shifts
        .get(round % 4)
        .ok_or(super::Md5BackendError::Quarantined)?;
    Ok((index, *shift))
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
