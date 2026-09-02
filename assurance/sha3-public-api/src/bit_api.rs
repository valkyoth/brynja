//! Package-external FIPS 202 bit-domain acceptance.

use brynja::crypto as facade;
use brynja_hash_sha3 as leaf;

use crate::AcceptanceError;

pub(crate) fn check() -> Result<usize, AcceptanceError> {
    let leaf_input = leaf::Fips202BitString::new(&[0x13], 5)
        .map_err(|_| AcceptanceError::BitApiMismatch)?;
    let facade_input = facade::Fips202BitString::new(&[0x13], 5)
        .map_err(|_| AcceptanceError::BitApiMismatch)?;
    if leaf::sha3_224_bits(leaf_input).map_err(|_| AcceptanceError::BitApiMismatch)?
        != facade::sha3_224_bits(facade_input).map_err(|_| AcceptanceError::BitApiMismatch)?
        || leaf::sha3_256_bits(leaf_input).map_err(|_| AcceptanceError::BitApiMismatch)?
            != facade::sha3_256_bits(facade_input).map_err(|_| AcceptanceError::BitApiMismatch)?
        || leaf::sha3_384_bits(leaf_input).map_err(|_| AcceptanceError::BitApiMismatch)?
            != facade::sha3_384_bits(facade_input).map_err(|_| AcceptanceError::BitApiMismatch)?
        || leaf::sha3_512_bits(leaf_input).map_err(|_| AcceptanceError::BitApiMismatch)?
            != facade::sha3_512_bits(facade_input).map_err(|_| AcceptanceError::BitApiMismatch)?
    {
        return Err(AcceptanceError::BitApiMismatch);
    }
    check_streaming_fixed()?;
    check_shake128(leaf_input, facade_input)?;
    check_shake256(leaf_input, facade_input)?;
    Ok(8)
}

fn check_streaming_fixed() -> Result<(), AcceptanceError> {
    let whole = leaf::Fips202BitString::new(&[b'a', 0x13], 5)
        .map_err(|_| AcceptanceError::BitApiMismatch)?;
    let tail = leaf::Fips202BitString::new(&[0x13], 5)
        .map_err(|_| AcceptanceError::BitApiMismatch)?;
    let mut state = leaf::Sha3_256::new();
    state.update(b"a").map_err(|_| AcceptanceError::BitApiMismatch)?;
    if state.finalize_bits(tail).map_err(|_| AcceptanceError::BitApiMismatch)?
        != leaf::sha3_256_bits(whole).map_err(|_| AcceptanceError::BitApiMismatch)?
    {
        return Err(AcceptanceError::BitApiMismatch);
    }
    Ok(())
}

fn check_shake128(
    leaf_input: leaf::Fips202BitString<'_>,
    facade_input: facade::Fips202BitString<'_>,
) -> Result<(), AcceptanceError> {
    let mut leaf_bytes = [0xff_u8; 13];
    let mut facade_bytes = [0xff_u8; 13];
    let leaf_output = leaf::Fips202Output::new(&mut leaf_bytes, 4)
        .map_err(|_| AcceptanceError::BitApiMismatch)?;
    let facade_output = facade::Fips202Output::new(&mut facade_bytes, 4)
        .map_err(|_| AcceptanceError::BitApiMismatch)?;
    leaf::shake128_bits(leaf_input, leaf_output).map_err(|_| AcceptanceError::BitApiMismatch)?;
    facade::shake128_bits(facade_input, facade_output)
        .map_err(|_| AcceptanceError::BitApiMismatch)?;
    if leaf_bytes != facade_bytes || leaf_bytes.last().copied().unwrap_or(0) & 0xf0 != 0 {
        return Err(AcceptanceError::BitApiMismatch);
    }
    let mut reader = leaf::Shake128::new()
        .finalize_bits_xof(leaf_input)
        .map_err(|_| AcceptanceError::BitApiMismatch)?;
    let mut prefix = [0_u8; 12];
    reader.squeeze(&mut prefix).map_err(|_| AcceptanceError::BitApiMismatch)?;
    let mut tail = [0xff_u8; 1];
    let output = leaf::Fips202Output::new(&mut tail, 4)
        .map_err(|_| AcceptanceError::BitApiMismatch)?;
    reader.squeeze_final_bits(output).map_err(|_| AcceptanceError::BitApiMismatch)?;
    if prefix != leaf_bytes[..12] || tail.first() != leaf_bytes.last() {
        return Err(AcceptanceError::BitApiMismatch);
    }
    Ok(())
}

fn check_shake256(
    leaf_input: leaf::Fips202BitString<'_>,
    facade_input: facade::Fips202BitString<'_>,
) -> Result<(), AcceptanceError> {
    let mut leaf_bytes = [0xff_u8; 14];
    let mut facade_bytes = [0xff_u8; 14];
    let leaf_output = leaf::Fips202Output::new(&mut leaf_bytes, 5)
        .map_err(|_| AcceptanceError::BitApiMismatch)?;
    let facade_output = facade::Fips202Output::new(&mut facade_bytes, 5)
        .map_err(|_| AcceptanceError::BitApiMismatch)?;
    leaf::shake256_bits(leaf_input, leaf_output).map_err(|_| AcceptanceError::BitApiMismatch)?;
    facade::shake256_bits(facade_input, facade_output)
        .map_err(|_| AcceptanceError::BitApiMismatch)?;
    if leaf_bytes != facade_bytes || leaf_bytes.last().copied().unwrap_or(0) & 0xe0 != 0 {
        return Err(AcceptanceError::BitApiMismatch);
    }
    Ok(())
}
