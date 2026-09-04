#![no_std]

use brynja_hash_tuple::{HardenedTupleHash128, TupleHashError, TupleHashXof256};

/// Hashes a tuple through the leaf package.
pub fn leaf(items: &[&[u8]], output: &mut [u8; 32]) -> Result<(), TupleHashError> {
    brynja_hash_tuple::tuple_hash128(items, b"package-external", output)
}

/// Hashes a tuple through the cryptographic facade.
pub fn crypto(items: &[&[u8]], output: &mut [u8; 32]) -> Result<(), TupleHashError> {
    brynja_crypto::tuple_hash128(items, b"package-external", output)
}

/// Hashes a tuple through the main facade.
pub fn facade(items: &[&[u8]], output: &mut [u8; 32]) -> Result<(), TupleHashError> {
    brynja::crypto::tuple_hash128(items, b"package-external", output)
}

/// Exercises the main facade's arbitrary-bit TupleHashXOF convenience API.
pub fn bit_xof(output: &mut [u8; 3]) -> Result<(), TupleHashError> {
    let item = brynja::crypto::Fips202BitString::new(&[0b0001_0101], 5)
        .map_err(|_| TupleHashError::InvalidBitString)?;
    let custom = brynja::crypto::Fips202BitString::new(&[], 0)
        .map_err(|_| TupleHashError::InvalidBitString)?;
    let destination = brynja::crypto::Fips202Output::new(output, 3)
        .map_err(|_| TupleHashError::InvalidBitString)?;
    brynja::crypto::tuple_hash_xof128_bits(&[item], custom, destination)
}

/// Exercises exact-length streaming and incremental XOF output.
pub fn streaming(output: &mut [u8; 48]) -> Result<(), TupleHashError> {
    let mut state = TupleHashXof256::new(b"package-external")?;
    {
        let mut item = state.begin_item(48)?;
        item.update(b"ab")?;
        item.update(b"cdef")?;
        item.finish()?;
    }
    let mut reader = state.finalize_xof()?;
    let (first, second) = output.split_at_mut(13);
    reader.squeeze(first)?;
    reader.squeeze(second)
}

/// Exercises typed secret output and cleanup.
pub fn hardened(output: &mut [u8; 32]) -> Result<(), TupleHashError> {
    let mut state = HardenedTupleHash128::new(b"package-external")?;
    state.push_item(b"secret-derived item")?;
    let secret = state.finalize_secret(output)?;
    if secret.expose().len() != 32 {
        return Err(TupleHashError::SecretMemory);
    }
    drop(secret);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn leaf_crypto_and_main_facades_are_operational() {
        let items: &[&[u8]] = &[b"ab", b"c"];
        let mut leaf = [0; 32];
        let mut crypto = [0; 32];
        let mut facade = [0; 32];
        let mut stream = [0; 48];
        let mut secret = [0xa5; 32];
        let mut bit_xof = [0xff; 3];
        assert_eq!(super::leaf(items, &mut leaf), Ok(()));
        assert_eq!(super::crypto(items, &mut crypto), Ok(()));
        assert_eq!(super::facade(items, &mut facade), Ok(()));
        assert_eq!(leaf, crypto);
        assert_eq!(leaf, facade);
        assert_eq!(super::streaming(&mut stream), Ok(()));
        assert!(stream.iter().any(|byte| *byte != 0));
        assert_eq!(super::hardened(&mut secret), Ok(()));
        assert!(secret.iter().all(|byte| *byte == 0));
        assert_eq!(super::bit_xof(&mut bit_xof), Ok(()));
        assert_eq!(bit_xof[2] & 0b1111_1000, 0);
    }
}
