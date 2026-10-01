//! Explicit accelerated protocol, never a scalar-image fallback.
use super::{Error, tuple_wire::Request};
pub(super) const PROTOCOL: usize = 0x42525432;

pub(super) fn header(request: Request, input: &[u8]) -> Result<[u8; 112], Error> {
    let scalar = request.header(input)?;
    let mut bytes = [0; 112];
    bytes
        .get_mut(..96)
        .ok_or(Error::Bounds)?
        .copy_from_slice(&scalar);
    bytes
        .get_mut(..8)
        .ok_or(Error::Bounds)?
        .copy_from_slice(&16_u64.to_le_bytes());
    bytes
        .get_mut(96..104)
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
    super::tuple_receipt::receipt_width(low, operation, length, value, 112)
}
