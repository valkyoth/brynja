use brynja_hash_sha3::{Fips202BitString, Fips202Output};
use brynja_hash_tuple::{
    HardenedTupleHash128, HardenedTupleHash256, HardenedTupleHashXof128,
    HardenedTupleHashXof256, TupleHash128, TupleHash256, TupleHashXof128, TupleHashXof256,
    tuple_hash_xof128, tuple_hash_xof256, tuple_hash128, tuple_hash256,
};

use crate::{AcceptanceError, hex_eq, vectors};

const FIRST: &[u8] = &[0x00, 0x01, 0x02];
const SECOND: &[u8] = &[0x10, 0x11, 0x12, 0x13, 0x14, 0x15];

pub(crate) fn run() -> Result<(), AcceptanceError> {
    official_examples()?;
    streaming_bits_and_boundaries()?;
    hardened_profiles()?;
    Ok(())
}

fn official_examples() -> Result<(), AcceptanceError> {
    let items: &[&[u8]] = &[FIRST, SECOND];
    let mut fixed128 = [0_u8; 32];
    let mut fixed256 = [0_u8; 64];
    let mut xof128 = [0_u8; 32];
    let mut xof256 = [0_u8; 64];
    tuple_hash128(items, b"", &mut fixed128).map_err(|_| AcceptanceError::TupleHash)?;
    tuple_hash256(items, b"", &mut fixed256).map_err(|_| AcceptanceError::TupleHash)?;
    tuple_hash_xof128(items, b"", &mut xof128).map_err(|_| AcceptanceError::TupleHash)?;
    tuple_hash_xof256(items, b"", &mut xof256).map_err(|_| AcceptanceError::TupleHash)?;
    if !hex_eq(&fixed128, vectors::TUPLE128)
        || !hex_eq(&fixed256, vectors::TUPLE256)
        || !hex_eq(&xof128, vectors::TUPLEXOF128)
        || !hex_eq(&xof256, vectors::TUPLEXOF256)
    {
        return Err(AcceptanceError::TupleHash);
    }
    Ok(())
}

fn streaming_bits_and_boundaries() -> Result<(), AcceptanceError> {
    let mut fixed = TupleHash128::new(b"").map_err(|_| AcceptanceError::TupleHash)?;
    fixed.push_item(FIRST).map_err(|_| AcceptanceError::TupleHash)?;
    {
        let mut item = fixed.begin_item(48).map_err(|_| AcceptanceError::TupleHash)?;
        item.update(&SECOND[..2]).map_err(|_| AcceptanceError::TupleHash)?;
        item.update(&SECOND[2..]).map_err(|_| AcceptanceError::TupleHash)?;
        item.finish().map_err(|_| AcceptanceError::TupleHash)?;
    }
    let mut fixed_output = [0_u8; 32];
    fixed
        .finalize(&mut fixed_output)
        .map_err(|_| AcceptanceError::TupleHash)?;
    if !hex_eq(&fixed_output, vectors::TUPLE128) {
        return Err(AcceptanceError::TupleHash);
    }

    let mut xof128 = TupleHashXof128::new(b"").map_err(|_| AcceptanceError::TupleHash)?;
    xof128.push_item(FIRST).map_err(|_| AcceptanceError::TupleHash)?;
    xof128.push_item(SECOND).map_err(|_| AcceptanceError::TupleHash)?;
    let mut reader128 = xof128.finalize_xof().map_err(|_| AcceptanceError::TupleHash)?;
    let mut xof_output128 = [0_u8; 32];
    let (first, second) = xof_output128.split_at_mut(9);
    reader128.squeeze(first).map_err(|_| AcceptanceError::TupleHash)?;
    reader128.squeeze(second).map_err(|_| AcceptanceError::TupleHash)?;

    let mut xof256 = TupleHashXof256::new(b"").map_err(|_| AcceptanceError::TupleHash)?;
    xof256.push_item(FIRST).map_err(|_| AcceptanceError::TupleHash)?;
    xof256.push_item(SECOND).map_err(|_| AcceptanceError::TupleHash)?;
    let mut reader256 = xof256.finalize_xof().map_err(|_| AcceptanceError::TupleHash)?;
    let mut xof_output256 = [0_u8; 64];
    let (first, second) = xof_output256.split_at_mut(31);
    reader256.squeeze(first).map_err(|_| AcceptanceError::TupleHash)?;
    reader256.squeeze(second).map_err(|_| AcceptanceError::TupleHash)?;
    if !hex_eq(&xof_output128, vectors::TUPLEXOF128)
        || !hex_eq(&xof_output256, vectors::TUPLEXOF256)
    {
        return Err(AcceptanceError::TupleHash);
    }

    let custom = Fips202BitString::new(&[], 0).map_err(|_| AcceptanceError::TupleHash)?;
    let item = Fips202BitString::new(&[0x15], 5).map_err(|_| AcceptanceError::TupleHash)?;
    let mut state = TupleHash256::new_bits(custom).map_err(|_| AcceptanceError::TupleHash)?;
    state.push_item_bits(item).map_err(|_| AcceptanceError::TupleHash)?;
    let mut bits = [0_u8; 17];
    let output = Fips202Output::new(&mut bits, 3).map_err(|_| AcceptanceError::TupleHash)?;
    state.finalize_bits(output).map_err(|_| AcceptanceError::TupleHash)?;
    if bits[16] & 0xf8 != 0 {
        return Err(AcceptanceError::TupleHash);
    }
    let mut empty = [0_u8; 1];
    tuple_hash128(&[], b"", &mut empty).map_err(|_| AcceptanceError::TupleHash)
}

fn hardened_profiles() -> Result<(), AcceptanceError> {
    let items: &[&[u8]] = &[b"secret item"];
    let mut expected_fixed128 = [0_u8; 32];
    let mut expected_fixed256 = [0_u8; 64];
    let mut expected_xof128 = [0_u8; 37];
    let mut expected_xof256 = [0_u8; 73];
    tuple_hash128(items, b"secret", &mut expected_fixed128)
        .map_err(|_| AcceptanceError::TupleHash)?;
    tuple_hash256(items, b"secret", &mut expected_fixed256)
        .map_err(|_| AcceptanceError::TupleHash)?;
    tuple_hash_xof128(items, b"secret", &mut expected_xof128)
        .map_err(|_| AcceptanceError::TupleHash)?;
    tuple_hash_xof256(items, b"secret", &mut expected_xof256)
        .map_err(|_| AcceptanceError::TupleHash)?;
    let mut fixed128 = [0xa5_u8; 32];
    let mut fixed256 = [0xa5_u8; 64];
    let mut xof128 = [0xa5_u8; 37];
    let mut xof256 = [0xa5_u8; 73];
    {
        let mut state = HardenedTupleHash128::new(b"secret")
            .map_err(|_| AcceptanceError::TupleHash)?;
        state.push_item(b"secret item").map_err(|_| AcceptanceError::TupleHash)?;
        let secret = state
            .finalize_secret(&mut fixed128)
            .map_err(|_| AcceptanceError::TupleHash)?;
        if secret.expose() != expected_fixed128 {
            return Err(AcceptanceError::TupleHash);
        }
    }
    {
        let mut state = HardenedTupleHash256::new(b"secret")
            .map_err(|_| AcceptanceError::TupleHash)?;
        state.push_item(b"secret item").map_err(|_| AcceptanceError::TupleHash)?;
        let secret = state
            .finalize_secret(&mut fixed256)
            .map_err(|_| AcceptanceError::TupleHash)?;
        if secret.expose() != expected_fixed256 {
            return Err(AcceptanceError::TupleHash);
        }
    }
    {
        let mut state = HardenedTupleHashXof128::new(b"secret")
            .map_err(|_| AcceptanceError::TupleHash)?;
        state.push_item(b"secret item").map_err(|_| AcceptanceError::TupleHash)?;
        let mut reader = state.finalize_xof().map_err(|_| AcceptanceError::TupleHash)?;
        let secret = reader
            .squeeze_secret(&mut xof128)
            .map_err(|_| AcceptanceError::TupleHash)?;
        if secret.expose() != expected_xof128 {
            return Err(AcceptanceError::TupleHash);
        }
    }
    {
        let mut state = HardenedTupleHashXof256::new(b"secret")
            .map_err(|_| AcceptanceError::TupleHash)?;
        state.push_item(b"secret item").map_err(|_| AcceptanceError::TupleHash)?;
        let mut reader = state.finalize_xof().map_err(|_| AcceptanceError::TupleHash)?;
        let secret = reader
            .squeeze_secret(&mut xof256)
            .map_err(|_| AcceptanceError::TupleHash)?;
        if secret.expose() != expected_xof256 {
            return Err(AcceptanceError::TupleHash);
        }
    }
    if fixed128 != [0; 32] || fixed256 != [0; 64] || xof128 != [0; 37] || xof256 != [0; 73] {
        return Err(AcceptanceError::TupleHash);
    }
    Ok(())
}
