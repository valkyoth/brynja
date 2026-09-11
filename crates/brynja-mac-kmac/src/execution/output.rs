use super::{Error, core_state::Core};
use crate::{Fips202BitString, KmacVerification, output::VerificationDifference};
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
    u128::try_from(length.checked_sub(1).ok_or(Error::OutputTooLong)?)
        .ok()
        .and_then(|n| n.checked_mul(8))
        .and_then(|n| n.checked_add(u128::from(valid)))
        .ok_or(Error::OutputTooLong)
}

pub(super) fn valid(length: usize) -> u8 {
    if length == 0 { 0 } else { 8 }
}

pub(super) fn verify(
    core: &mut Core<'_>,
    candidate: Fips202BitString<'_>,
) -> Result<KmacVerification, Error> {
    let mut difference = VerificationDifference::new();
    let length = candidate.as_bytes().len();
    let mut position = 0_usize;
    for expected in candidate.as_bytes().chunks(64) {
        let mut generated = Stage([0; 168]);
        position = position
            .checked_add(expected.len())
            .ok_or(Error::OutputTooLong)?;
        let last = position == length;
        let valid = if last {
            candidate.valid_bits_in_last_byte()
        } else {
            8
        };
        let destination = generated
            .0
            .get_mut(..expected.len())
            .ok_or(Error::OutputTooLong)?;
        let secret = core.secret(destination, valid, last)?;
        for (actual, expected) in secret.expose().iter().zip(expected) {
            difference.accumulate(*actual ^ *expected);
        }
    }
    core.cancel();
    Ok(KmacVerification::new(difference.is_zero()))
}
