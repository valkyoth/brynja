#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use crate::static_execution::Error;
use brynja_core::clear_owned_region;

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use crate::keccak_constants::{PI_DESTINATIONS, ROTATION_OFFSETS};

/// Every source-owned aggregate temporary used by the hardened permutation.
/// Scalar/vector register values and compiler-created copies remain residuals.
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

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
impl KeccakScratch {
    pub(crate) fn theta_rho_pi(&mut self) -> Result<(), Error> {
        for x in 0_usize..5 {
            let mut parity = 0_u64;
            for y in 0_usize..5 {
                parity ^= read(&self.lanes, x.saturating_add(y.saturating_mul(5)))?;
            }
            write(&mut self.columns, x, parity)?;
        }
        for x in 0_usize..5 {
            let delta = read(&self.columns, x.saturating_add(4) % 5)?
                ^ read(&self.columns, x.saturating_add(1) % 5)?.rotate_left(1);
            write(&mut self.theta, x, delta)?;
        }
        for ((index, rotation), destination) in ROTATION_OFFSETS
            .into_iter()
            .enumerate()
            .zip(PI_DESTINATIONS)
        {
            let value = read(&self.lanes, index)? ^ read(&self.theta, index % 5)?;
            write(
                &mut self.rearranged,
                destination,
                value.rotate_left(rotation),
            )?;
        }
        Ok(())
    }

    pub(crate) fn stage_chi(
        &mut self,
        row: usize,
        first: usize,
        width: usize,
    ) -> Result<(), Error> {
        check_chi(row, first, width)?;
        for lane in 0..width {
            write(
                &mut self.current,
                lane,
                read(
                    &self.rearranged,
                    row.saturating_mul(5)
                        .saturating_add(first)
                        .saturating_add(lane),
                )?,
            )?;
            write(
                &mut self.next,
                lane,
                read(
                    &self.rearranged,
                    row.saturating_mul(5)
                        .saturating_add(first.saturating_add(lane).saturating_add(1) % 5),
                )?,
            )?;
            write(
                &mut self.following,
                lane,
                read(
                    &self.rearranged,
                    row.saturating_mul(5)
                        .saturating_add(first.saturating_add(lane).saturating_add(2) % 5),
                )?,
            )?;
        }
        Ok(())
    }

    pub(crate) fn commit_chi(
        &mut self,
        row: usize,
        first: usize,
        width: usize,
    ) -> Result<(), Error> {
        check_chi(row, first, width)?;
        for lane in 0..width {
            write(
                &mut self.lanes,
                row.saturating_mul(5)
                    .saturating_add(first)
                    .saturating_add(lane),
                read(&self.current, lane)?,
            )?;
        }
        Ok(())
    }

    pub(crate) fn last_chi(&mut self, row: usize) -> Result<(), Error> {
        check_chi(row, 4, 1)?;
        let first = row.saturating_mul(5);
        let value = read(&self.rearranged, first.saturating_add(4))?
            ^ ((!read(&self.rearranged, first)?)
                & read(&self.rearranged, first.saturating_add(1))?);
        write(&mut self.lanes, first.saturating_add(4), value)
    }

    pub(crate) fn iota(&mut self, constant: u64) -> Result<(), Error> {
        let value = read(&self.lanes, 0)? ^ constant;
        write(&mut self.lanes, 0, value)
    }
}

impl Drop for KeccakScratch {
    fn drop(&mut self) {
        self.wipe();
    }
}

// An internal invariant violation aborts the operation before caller-state commit.
// The session's operation guard clears scratch and quarantines its authority.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn check_chi(row: usize, first: usize, width: usize) -> Result<(), Error> {
    if row >= 5 || width == 0 || width > 4 || first.checked_add(width).is_none_or(|end| end > 5) {
        return Err(Error::Quarantined);
    }
    Ok(())
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn read(bytes: &[u8], index: usize) -> Result<u64, Error> {
    let mut value = 0_u64;
    let word = bytes
        .as_chunks::<8>()
        .0
        .get(index)
        .ok_or(Error::Quarantined)?;
    for (offset, byte) in word.iter().enumerate() {
        value |= u64::from(*byte) << offset.saturating_mul(8);
    }
    Ok(value)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn write(bytes: &mut [u8], index: usize, value: u64) -> Result<(), Error> {
    let word = bytes
        .as_chunks_mut::<8>()
        .0
        .get_mut(index)
        .ok_or(Error::Quarantined)?;
    for (offset, byte) in word.iter_mut().enumerate() {
        *byte = u8::try_from((value >> offset.saturating_mul(8)) & 255).unwrap_or_default();
    }
    Ok(())
}

#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
pub(super) fn check_invalid_indices() -> Result<(), Error> {
    for length in [0_usize, 7, 8, 32, 40, 200] {
        let mut bytes = [0xa5; 200];
        let words = length / 8;
        let region = bytes.get_mut(..length).ok_or(Error::Quarantined)?;
        for index in [words, words.saturating_add(1), usize::MAX] {
            assert_eq!(read(region, index), Err(Error::Quarantined));
            assert_eq!(write(region, index, 0), Err(Error::Quarantined));
            assert!(region.iter().all(|byte| *byte == 0xa5));
        }
        for index in 0..words {
            assert_eq!(write(region, index, 0x1234_5678_9abc_def0), Ok(()));
            assert_eq!(read(region, index), Ok(0x1234_5678_9abc_def0));
        }
    }
    let mut scratch = KeccakScratch::new();
    for (row, first, width) in [
        (5, 0, 4),
        (0, 4, 2),
        (0, 0, 5),
        (0, 0, 0),
        (0, usize::MAX, 1),
    ] {
        assert_eq!(
            scratch.stage_chi(row, first, width),
            Err(Error::Quarantined)
        );
        assert_eq!(
            scratch.commit_chi(row, first, width),
            Err(Error::Quarantined)
        );
    }
    assert_eq!(scratch.last_chi(usize::MAX), Err(Error::Quarantined));
    Ok(())
}
