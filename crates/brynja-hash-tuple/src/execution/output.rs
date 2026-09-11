use super::{Error, core_state::Core};
use crate::TupleHashSecretOutput;
use brynja_core::clear_owned_region;

pub(super) struct Stage(pub(super) [u8; 168]);
impl Drop for Stage {
    fn drop(&mut self) {
        let _ = clear_owned_region(&mut self.0);
    }
}
pub(super) struct BorrowedStage<'a>(pub(super) &'a mut [u8]);
impl Drop for BorrowedStage<'_> {
    fn drop(&mut self) {
        let _ = clear_owned_region(self.0);
    }
}
pub(super) fn valid(length: usize) -> u8 {
    if length == 0 { 0 } else { 8 }
}
pub(super) fn byte_bits(length: usize) -> Result<u128, Error> {
    u128::try_from(length)
        .ok()
        .and_then(|n| n.checked_mul(8))
        .ok_or(Error::OutputTooLong)
}
pub(super) fn length_bits(length: usize, valid: u8) -> Result<u128, Error> {
    if length == 0 {
        return if valid == 0 {
            Ok(0)
        } else {
            Err(Error::InvalidBitString)
        };
    }
    if !(1..=8).contains(&valid) {
        return Err(Error::InvalidBitString);
    }
    byte_bits(length.checked_sub(1).ok_or(Error::OutputTooLong)?)?
        .checked_add(u128::from(valid))
        .ok_or(Error::OutputTooLong)
}

// These helpers borrow the exact inline owner; public finalizers consume only
// at the API boundary, never by moving a secret-bearing inner Core into a helper.
pub(super) fn fixed_public(
    core: &mut Core<'_>,
    bytes: &mut [u8],
    valid: u8,
    scratch: &mut [u8],
) -> Result<(), Error> {
    let stage = BorrowedStage(scratch);
    let bits = length_bits(bytes.len(), valid)?;
    core.finish(bits)?;
    core.public(bytes, valid, stage.0, true)
}
pub(super) fn fixed_secret<'out>(
    core: &mut Core<'_>,
    bytes: &'out mut [u8],
    valid: u8,
) -> Result<TupleHashSecretOutput<'out>, Error> {
    let _ = clear_owned_region(bytes);
    let bits = length_bits(bytes.len(), valid)?;
    core.finish(bits)?;
    core.secret(bytes, valid, true)
}
