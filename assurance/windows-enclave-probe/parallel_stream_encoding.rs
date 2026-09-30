//! Clearing integer encoding adapted from the first-party ParallelHash owner.
use super::Error;
use brynja_core::clear_owned_region;

/// Empty storage is established before accepting potentially private counters.
pub(super) struct SecretEncodedInteger {
    bytes: [u8; 17],
    length: [u8; 1],
}
impl SecretEncodedInteger {
    pub(super) const fn empty() -> Self {
        Self {
            bytes: [0; 17],
            length: [0],
        }
    }
    pub(super) fn left(&mut self, value: u128) -> Result<(), Error> {
        write(&mut self.bytes, &mut self.length, value, true)
    }
    pub(super) fn right(&mut self, value: u128) -> Result<(), Error> {
        write(&mut self.bytes, &mut self.length, value, false)
    }
    pub(super) fn bytes(&self) -> Result<&[u8], Error> {
        bytes(&self.bytes, &self.length)
    }
}
impl Drop for SecretEncodedInteger {
    fn drop(&mut self) {
        let _ = clear_owned_region(&mut self.bytes);
        let _ = clear_owned_region(&mut self.length);
    }
}

pub(super) fn bytes<'a>(storage: &'a [u8; 17], length: &[u8; 1]) -> Result<&'a [u8], Error> {
    let count = usize::from(length[0]);
    if !(2..=17).contains(&count) {
        return Err(Error::State);
    }
    storage.get(..count).ok_or(Error::State)
}

/// Fill borrowed storage, clearing any prior encoding first. Publish length last.
pub(super) fn write(
    storage: &mut [u8; 17],
    length: &mut [u8; 1],
    value: u128,
    left: bool,
) -> Result<(), Error> {
    let _ = clear_owned_region(storage);
    let _ = clear_owned_region(length);
    let mut width = 1_usize;
    let mut remaining = value;
    while remaining > 255 {
        width = width.checked_add(1).ok_or(Error::Length)?;
        remaining >>= 8;
    }
    let marker = if left { 0 } else { width };
    *storage.get_mut(marker).ok_or(Error::State)? =
        u8::try_from(width).map_err(|_| Error::Length)?;
    for index in 0..width {
        let shift = width
            .checked_sub(index)
            .and_then(|v| v.checked_sub(1))
            .and_then(|v| v.checked_mul(8))
            .ok_or(Error::Length)?;
        let position = index.checked_add(usize::from(left)).ok_or(Error::Length)?;
        *storage.get_mut(position).ok_or(Error::State)? =
            u8::try_from((value >> shift) & 255).map_err(|_| Error::Length)?;
    }
    length[0] =
        u8::try_from(width.checked_add(1).ok_or(Error::Length)?).map_err(|_| Error::Length)?;
    Ok(())
}
