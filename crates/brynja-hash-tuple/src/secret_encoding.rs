use brynja_core::clear_owned_region;

use crate::TupleHashError;

pub(crate) struct SecretEncodedInteger {
    bytes: [u8; 17],
    length: [u8; 1],
}

impl SecretEncodedInteger {
    /// Construct empty storage before accepting length metadata. Populated
    /// encodings are written through a borrow, never returned as owning values.
    pub(crate) const fn empty() -> Self {
        Self {
            bytes: [0; 17],
            length: [0],
        }
    }

    pub(crate) fn left(&mut self, value: u128) -> Result<(), TupleHashError> {
        self.reset();
        let width = encoded_width(value)?;
        let Some(prefix) = self.bytes.first_mut() else {
            return Err(TupleHashError::SecretMemory);
        };
        *prefix = width;
        self.write_value(value, 1, width)?;
        self.length = [width.checked_add(1).ok_or(TupleHashError::MessageTooLong)?];
        Ok(())
    }

    pub(crate) fn right(&mut self, value: u128) -> Result<(), TupleHashError> {
        self.reset();
        let width = encoded_width(value)?;
        self.write_value(value, 0, width)?;
        let width_position = usize::from(width);
        let Some(suffix) = self.bytes.get_mut(width_position) else {
            return Err(TupleHashError::SecretMemory);
        };
        *suffix = width;
        self.length = [width.checked_add(1).ok_or(TupleHashError::MessageTooLong)?];
        Ok(())
    }

    pub(crate) fn as_bytes(&self) -> Result<&[u8], TupleHashError> {
        let length = usize::from(self.length.first().copied().unwrap_or_default());
        if !(2..=17).contains(&length) {
            return Err(TupleHashError::SecretMemory);
        }
        self.bytes.get(..length).ok_or(TupleHashError::SecretMemory)
    }

    fn reset(&mut self) {
        let _ = clear_owned_region(&mut self.bytes);
        let _ = clear_owned_region(&mut self.length);
    }

    fn write_value(&mut self, value: u128, offset: usize, width: u8) -> Result<(), TupleHashError> {
        for index in 0..usize::from(width) {
            let reverse = usize::from(width)
                .checked_sub(index)
                .and_then(|position| position.checked_sub(1))
                .ok_or(TupleHashError::MessageTooLong)?;
            let shift = reverse
                .checked_mul(8)
                .ok_or(TupleHashError::MessageTooLong)?;
            let byte = u8::try_from((value >> shift) & u128::from(u8::MAX))
                .map_err(|_| TupleHashError::MessageTooLong)?;
            let position = offset
                .checked_add(index)
                .ok_or(TupleHashError::MessageTooLong)?;
            let Some(target) = self.bytes.get_mut(position) else {
                return Err(TupleHashError::SecretMemory);
            };
            *target = byte;
        }
        Ok(())
    }
}

impl Drop for SecretEncodedInteger {
    fn drop(&mut self) {
        let _ = clear_owned_region(&mut self.bytes);
        let _ = clear_owned_region(&mut self.length);
    }
}

fn encoded_width(value: u128) -> Result<u8, TupleHashError> {
    let mut remaining = value;
    let mut width = 1_u8;
    while remaining > u128::from(u8::MAX) {
        width = width.checked_add(1).ok_or(TupleHashError::MessageTooLong)?;
        remaining >>= 8;
    }
    Ok(width)
}

#[cfg(test)]
mod tests {
    use brynja_hash_sha3::{left_encode_u128, right_encode_u128};

    use super::SecretEncodedInteger;

    #[test]
    fn clearing_encoders_match_sp800185_for_boundary_values() {
        for value in [0, 1, 255, 256, 65_535, u128::MAX] {
            let mut left = SecretEncodedInteger::empty();
            assert_eq!(left.left(value), Ok(()));
            assert_eq!(left.as_bytes(), Ok(left_encode_u128(value).as_bytes()));

            let mut right = SecretEncodedInteger::empty();
            assert_eq!(right.right(value), Ok(()));
            assert_eq!(right.as_bytes(), Ok(right_encode_u128(value).as_bytes()));
        }
    }

    #[test]
    fn borrowed_encoding_reuse_clears_every_unused_byte_at_all_widths() {
        let mut encoded = SecretEncodedInteger::empty();
        for shift in 0..128 {
            let power = 1_u128 << shift;
            for value in [power - 1, power, power.saturating_add(1)] {
                for right in [false, true] {
                    assert_eq!(encoded.left(u128::MAX), Ok(()));
                    let expected = if right {
                        assert_eq!(encoded.right(value), Ok(()));
                        right_encode_u128(value)
                    } else {
                        assert_eq!(encoded.left(value), Ok(()));
                        left_encode_u128(value)
                    };
                    assert_eq!(encoded.as_bytes(), Ok(expected.as_bytes()));
                    assert_eq!(
                        encoded
                            .bytes
                            .get(expected.as_bytes().len()..)
                            .map(|tail| tail.iter().all(|b| *b == 0)),
                        Some(true)
                    );
                }
            }
        }
        encoded.reset();
        assert_eq!(encoded.bytes, [0; 17]);
        assert_eq!(encoded.length, [0]);
        assert_eq!(encoded.as_bytes(), Err(crate::TupleHashError::SecretMemory));
    }

    #[test]
    fn empty_and_corrupt_encoded_lengths_are_rejected() {
        let mut encoded = SecretEncodedInteger::empty();
        assert_eq!(encoded.as_bytes(), Err(crate::TupleHashError::SecretMemory));
        for length in [0, 1, 18, 255] {
            encoded.length = [length];
            assert_eq!(encoded.as_bytes(), Err(crate::TupleHashError::SecretMemory));
        }
    }
}
