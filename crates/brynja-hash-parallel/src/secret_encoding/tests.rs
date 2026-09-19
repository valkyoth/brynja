use super::*;
use brynja_hash_sha3::{left_encode_u128, right_encode_u128};

#[test]
fn borrowed_integer_matches_every_width_and_clears_reuse() -> Result<(), ParallelHashError> {
    let mut owned = SecretEncodedInteger::empty();
    assert!(owned.bytes().is_err());
    for bit in 0..128 {
        let value = 1_u128 << bit;
        for value in [0, value - 1, value, value.saturating_add(1), u128::MAX] {
            for left in [true, false] {
                owned.bytes.fill(0xa5);
                owned.length = [255];
                if left {
                    owned.left(value)?;
                } else {
                    owned.right(value)?;
                }
                let expected = if left {
                    left_encode_u128(value)
                } else {
                    right_encode_u128(value)
                };
                assert_eq!(owned.bytes()?, expected.as_bytes());
                assert!(
                    owned
                        .bytes
                        .get(expected.as_bytes().len()..)
                        .ok_or(ParallelHashError::SecretMemory)?
                        .iter()
                        .all(|byte| *byte == 0)
                );
            }
        }
    }
    for invalid in [0, 1, 18, 255] {
        owned.length = [invalid];
        assert_eq!(owned.bytes(), Err(ParallelHashError::SecretMemory));
    }
    Ok(())
}

#[test]
fn borrowed_encoder_function_clears_all_prior_storage() -> Result<(), ParallelHashError> {
    let mut storage = [0xa5; 17];
    let mut length = [255];
    write(&mut storage, &mut length, 0, true)?;
    assert_eq!(&storage[..2], &[1, 0]);
    assert_eq!(&storage[2..], &[0; 15]);
    assert_eq!(length, [2]);
    write(&mut storage, &mut length, u128::MAX, false)?;
    assert_eq!(&storage[..16], &[255; 16]);
    assert_eq!(storage[16], 16);
    assert_eq!(length, [17]);
    write(&mut storage, &mut length, 0, false)?;
    assert_eq!(&storage[..2], &[0, 1]);
    assert_eq!(&storage[2..], &[0; 15]);
    Ok(())
}
