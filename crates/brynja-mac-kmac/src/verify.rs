use brynja_core::clear_owned_region;
use brynja_hash_sha3::{Fips202BitString, Fips202Output};

use crate::{
    backend::CshakeReader,
    error::KmacError,
    output::{KmacVerification, VerificationDifference},
};

const VERIFY_BLOCK: usize = 64;

pub(crate) fn verify_reader<R: CshakeReader>(
    mut reader: R,
    candidate: Fips202BitString<'_>,
) -> Result<KmacVerification, KmacError> {
    let complete_length = if candidate.is_byte_aligned() {
        candidate.as_bytes().len()
    } else {
        candidate.as_bytes().len().saturating_sub(1)
    };
    let complete = candidate
        .as_bytes()
        .get(..complete_length)
        .ok_or(KmacError::InvalidBitString)?;
    let mut difference = VerificationDifference::new();
    for expected in complete.chunks(VERIFY_BLOCK) {
        let mut generated = VerificationBlock::new();
        let destination = generated
            .bytes
            .get_mut(..expected.len())
            .ok_or(KmacError::OutputTooLong)?;
        let secret = reader
            .squeeze_secret(destination)
            .map_err(KmacError::from)?;
        for (left, right) in secret.expose().iter().zip(expected.iter()) {
            difference.accumulate(*left ^ *right);
        }
    }
    if !candidate.is_byte_aligned() {
        let expected = candidate
            .as_bytes()
            .last()
            .copied()
            .ok_or(KmacError::InvalidBitString)?;
        let valid = candidate.valid_bits_in_last_byte();
        let mut generated = VerificationBlock::new();
        let destination = generated
            .bytes
            .get_mut(..1)
            .ok_or(KmacError::OutputTooLong)?;
        let output =
            Fips202Output::new(destination, valid).map_err(|_| KmacError::InvalidBitString)?;
        let secret = reader
            .squeeze_final_bits_secret(output)
            .map_err(KmacError::from)?;
        let actual = secret.expose().first().copied().unwrap_or_default();
        difference.accumulate(actual ^ expected);
    }
    Ok(KmacVerification::new(difference.is_zero()))
}

struct VerificationBlock {
    bytes: [u8; VERIFY_BLOCK],
}

impl VerificationBlock {
    const fn new() -> Self {
        Self {
            bytes: [0; VERIFY_BLOCK],
        }
    }
}

impl Drop for VerificationBlock {
    fn drop(&mut self) {
        let _ = clear_owned_region(&mut self.bytes);
    }
}
