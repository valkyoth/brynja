//! Explicit accelerated protocol, never a scalar-image fallback.
use super::{Error, sha3_wire::Request};
pub(super) const PROTOCOL: usize = 0x42524b31;

pub(super) fn header(request: Request, input: &[u8]) -> Result<[u8; 112], Error> {
    let scalar = request.header(input)?;
    if (matches!(request.op, 21 | 24 | 25 | 28) && !(1..=8).contains(&request.algorithm))
        || (request.op == 28 && !matches!(request.algorithm, 7 | 8))
        || (matches!(request.op, 25 | 27)
            && ((request.width == 0 && request.last != 0)
                || (request.width != 0 && request.last == 0)))
    {
        return Err(Error::Bounds);
    }
    let mut bytes = [0; 112];
    bytes
        .get_mut(..96)
        .ok_or(Error::Bounds)?
        .copy_from_slice(&scalar);
    bytes
        .get_mut(..8)
        .ok_or(Error::Bounds)?
        .copy_from_slice(&14_u64.to_le_bytes());
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
    super::sha3_wire::receipt_width(low, operation, length, value, 112)
}
