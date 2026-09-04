use brynja_core::clear_owned_region;

use crate::TupleHashError;

pub(crate) struct SecretEncodedInteger {
    bytes: [u8; 17],
    length: [u8; 1],
}

impl SecretEncodedInteger {
    pub(crate) fn left(value: u128) -> Result<Self, TupleHashError> {
        let width = encoded_width(value)?;
        let mut encoded = Self::empty(width)?;
        let Some(prefix) = encoded.bytes.first_mut() else {
            return Err(TupleHashError::SecretMemory);
        };
        *prefix = width;
        encoded.write_value(value, 1, width)?;
        Ok(encoded)
    }

    pub(crate) fn right(value: u128) -> Result<Self, TupleHashError> {
        let width = encoded_width(value)?;
        let mut encoded = Self::empty(width)?;
        encoded.write_value(value, 0, width)?;
        let width_position = usize::from(width);
        let Some(suffix) = encoded.bytes.get_mut(width_position) else {
            return Err(TupleHashError::SecretMemory);
        };
        *suffix = width;
        Ok(encoded)
    }

    pub(crate) fn as_bytes(&self) -> Result<&[u8], TupleHashError> {
        let length = usize::from(self.length.first().copied().unwrap_or_default());
        self.bytes.get(..length).ok_or(TupleHashError::SecretMemory)
    }

    fn empty(width: u8) -> Result<Self, TupleHashError> {
        let length = width.checked_add(1).ok_or(TupleHashError::MessageTooLong)?;
        Ok(Self {
            bytes: [0; 17],
            length: [length],
        })
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
            let left = SecretEncodedInteger::left(value);
            assert!(left.is_ok());
            let Ok(left) = left else {
                return;
            };
            assert_eq!(left.as_bytes(), Ok(left_encode_u128(value).as_bytes()));

            let right = SecretEncodedInteger::right(value);
            assert!(right.is_ok());
            let Ok(right) = right else {
                return;
            };
            assert_eq!(right.as_bytes(), Ok(right_encode_u128(value).as_bytes()));
        }
    }
}
