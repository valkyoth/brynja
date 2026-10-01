//! Explicit accelerated protocol, never a scalar-image fallback.
use super::{Error, sha3_batch_wire::Request};
pub(super) const PROTOCOL: usize = 0x42524233;

pub(super) fn header(request: Request, input: &[u8]) -> Result<[u8; 304], Error> {
    let scalar = request.header(input)?;
    let mut bytes = [0; 304];
    bytes
        .get_mut(..288)
        .ok_or(Error::Bounds)?
        .copy_from_slice(&scalar);
    bytes
        .get_mut(..8)
        .ok_or(Error::Bounds)?
        .copy_from_slice(&17_u64.to_le_bytes());
    bytes
        .get_mut(288..296)
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
    super::sha3_batch_receipt::receipt_width(low, operation, length, value, 304)
}
