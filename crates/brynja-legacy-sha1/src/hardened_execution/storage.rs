//! Checked fixed-width access; rejected indexes never synthesize zero/no-op work.
use crate::Sha1BackendError;

pub(crate) fn vector(bytes: &[u8], group: usize) -> Result<&[u8; 16], Sha1BackendError> {
    let start = group.checked_mul(16).ok_or(Sha1BackendError::Quarantined)?;
    let end = start.checked_add(16).ok_or(Sha1BackendError::Quarantined)?;
    bytes
        .get(start..end)
        .and_then(|b| b.try_into().ok())
        .ok_or(Sha1BackendError::Quarantined)
}
pub(crate) fn vector_mut(
    bytes: &mut [u8],
    group: usize,
) -> Result<&mut [u8; 16], Sha1BackendError> {
    let start = group.checked_mul(16).ok_or(Sha1BackendError::Quarantined)?;
    let end = start.checked_add(16).ok_or(Sha1BackendError::Quarantined)?;
    bytes
        .get_mut(start..end)
        .and_then(|b| b.try_into().ok())
        .ok_or(Sha1BackendError::Quarantined)
}
pub(crate) fn read(bytes: &[u8], index: usize) -> Result<u32, Sha1BackendError> {
    let start = index.checked_mul(4).ok_or(Sha1BackendError::Quarantined)?;
    let end = start.checked_add(4).ok_or(Sha1BackendError::Quarantined)?;
    match bytes.get(start..end) {
        Some([a, b, c, d]) => Ok(u32::from_be_bytes([*a, *b, *c, *d])),
        _ => Err(Sha1BackendError::Quarantined),
    }
}
pub(crate) fn add(bytes: &mut [u8], index: usize, word: u32) -> Result<(), Sha1BackendError> {
    let value = read(bytes, index)?.wrapping_add(word);
    let start = index.checked_mul(4).ok_or(Sha1BackendError::Quarantined)?;
    let end = start.checked_add(4).ok_or(Sha1BackendError::Quarantined)?;
    let out = bytes
        .get_mut(start..end)
        .ok_or(Sha1BackendError::Quarantined)?;
    for (byte, shift) in out.iter_mut().zip([24, 16, 8, 0]) {
        *byte = u8::try_from((value >> shift) & 0xff).map_err(|_| Sha1BackendError::Quarantined)?;
    }
    Ok(())
}
