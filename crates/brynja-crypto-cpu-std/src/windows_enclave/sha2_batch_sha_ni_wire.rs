//! Explicit narrow accelerated protocol, never a scalar-image fallback.
use super::{Error, sha2_batch_wire::Request};
pub(super) const PROTOCOL: usize = 0x42524232;

pub(super) fn header(request: Request, input: &[u8]) -> Result<[u8; 144], Error> {
    let scalar = request.header(input)?;
    if request.plan.iter().any(|id| !matches!(id, 0..=2)) {
        return Err(Error::Bounds);
    }
    let mut bytes = [0; 144];
    bytes
        .get_mut(..128)
        .ok_or(Error::Bounds)?
        .copy_from_slice(&scalar);
    bytes
        .get_mut(..8)
        .ok_or(Error::Bounds)?
        .copy_from_slice(&19_u64.to_le_bytes());
    bytes
        .get_mut(128..136)
        .ok_or(Error::Bounds)?
        .copy_from_slice(&1_u64.to_le_bytes());
    Ok(bytes)
}
pub(super) fn receipt(
    low: usize,
    operation: usize,
    length: usize,
    value: [usize; 7],
) -> Result<(), Error> {
    super::sha2_batch_receipt::receipt_width(low, operation, length, value, 144)
}
