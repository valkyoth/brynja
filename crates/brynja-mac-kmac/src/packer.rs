use brynja_core::clear_owned_region;
use brynja_hash_sha3::{Fips202BitString, left_encode_u128, right_encode_u128};

use crate::{backend::CshakeState, error::KmacError};

const MAX_RATE: usize = 168;

pub(crate) fn absorb_key<S: CshakeState>(
    state: &mut S,
    key: Fips202BitString<'_>,
    rate: usize,
) -> Result<(), KmacError> {
    let key_bits = u128::try_from(key.bit_len()).map_err(|_| KmacError::MessageTooLong)?;
    let rate_value = u128::try_from(rate).map_err(|_| KmacError::MessageTooLong)?;
    let mut packer = SecretPacker::new(state);
    packer.push_bytes(left_encode_u128(rate_value).as_bytes())?;
    let key_length = SecretEncodedInteger::left_encode(key_bits)?;
    packer.push_bytes(key_length.as_bytes()?)?;
    packer.push_bit_string(key)?;
    packer.finish_bytepad(rate)
}

struct SecretEncodedInteger {
    bytes: [u8; 17],
    length: [u8; 1],
}

impl SecretEncodedInteger {
    fn left_encode(value: u128) -> Result<Self, KmacError> {
        let mut remaining = value;
        let mut width = 1_u8;
        while remaining > u128::from(u8::MAX) {
            width = width.checked_add(1).ok_or(KmacError::MessageTooLong)?;
            remaining >>= 8;
        }
        let total = width.checked_add(1).ok_or(KmacError::MessageTooLong)?;
        let mut encoded = Self {
            bytes: [0; 17],
            length: [total],
        };
        let Some(prefix) = encoded.bytes.first_mut() else {
            return Err(KmacError::SecretMemory);
        };
        *prefix = width;
        for offset in 0..usize::from(width) {
            let reverse = usize::from(width)
                .checked_sub(offset)
                .and_then(|position| position.checked_sub(1))
                .ok_or(KmacError::MessageTooLong)?;
            let shift = reverse.checked_mul(8).ok_or(KmacError::MessageTooLong)?;
            let byte = u8::try_from((value >> shift) & u128::from(u8::MAX))
                .map_err(|_| KmacError::MessageTooLong)?;
            let position = offset.checked_add(1).ok_or(KmacError::MessageTooLong)?;
            let Some(target) = encoded.bytes.get_mut(position) else {
                return Err(KmacError::SecretMemory);
            };
            *target = byte;
        }
        Ok(encoded)
    }

    fn as_bytes(&self) -> Result<&[u8], KmacError> {
        let length = usize::from(self.length.first().copied().unwrap_or_default());
        self.bytes.get(..length).ok_or(KmacError::SecretMemory)
    }
}

impl Drop for SecretEncodedInteger {
    fn drop(&mut self) {
        let _ = clear_owned_region(&mut self.bytes);
        let _ = clear_owned_region(&mut self.length);
    }
}

pub(crate) fn append_right_encode<S: CshakeState>(
    state: &mut S,
    final_message: Option<Fips202BitString<'_>>,
    output_bits: u128,
) -> Result<S::Reader, KmacError> {
    let mut packer = SecretPacker::new(state);
    if let Some(message) = final_message {
        packer.push_bit_string(message)?;
    }
    packer.push_bytes(right_encode_u128(output_bits).as_bytes())?;
    let tail = packer.finish_bits();
    match tail {
        Some(tail) => {
            let input = Fips202BitString::new(tail.as_bytes(), tail.valid())
                .map_err(|_| KmacError::InvalidBitString)?;
            state
                .finalize_bits_xof_erasing_source(input)
                .map_err(KmacError::from)
        }
        None => Ok(state.finalize_xof_erasing_source()),
    }
}

struct SecretPacker<'state, S: CshakeState> {
    state: &'state mut S,
    pending: [u8; 1],
    used: [u8; 1],
    emitted: [u8; core::mem::size_of::<usize>()],
}

impl<'state, S: CshakeState> SecretPacker<'state, S> {
    fn new(state: &'state mut S) -> Self {
        Self {
            state,
            pending: [0],
            used: [0],
            emitted: [0; core::mem::size_of::<usize>()],
        }
    }

    fn push_bit_string(&mut self, input: Fips202BitString<'_>) -> Result<(), KmacError> {
        if input.is_byte_aligned() {
            return self.push_bytes(input.as_bytes());
        }
        let complete_length = input.as_bytes().len().saturating_sub(1);
        let complete = input
            .as_bytes()
            .get(..complete_length)
            .ok_or(KmacError::InvalidBitString)?;
        self.push_bytes(complete)?;
        let tail = input
            .as_bytes()
            .last()
            .copied()
            .ok_or(KmacError::InvalidBitString)?;
        self.push_bits(tail, input.valid_bits_in_last_byte())
    }

    fn push_bytes(&mut self, input: &[u8]) -> Result<(), KmacError> {
        if self.used() == 0 {
            self.state.update(input).map_err(KmacError::from)?;
            let emitted = self
                .emitted()
                .checked_add(input.len())
                .ok_or(KmacError::MessageTooLong)?;
            self.set_emitted(emitted);
            return Ok(());
        }
        for byte in input {
            self.push_bits(*byte, 8)?;
        }
        Ok(())
    }

    fn push_bits(&mut self, byte: u8, valid: u8) -> Result<(), KmacError> {
        for position in 0..valid {
            let bit = (byte >> position) & 1;
            let used = self.used();
            let pending = self
                .pending
                .first_mut()
                .ok_or(KmacError::InvalidBitString)?;
            *pending |= bit << used;
            self.set_used(used.checked_add(1).ok_or(KmacError::MessageTooLong)?);
            if self.used() == 8 {
                self.flush()?;
            }
        }
        Ok(())
    }

    fn finish_bytepad(mut self, rate: usize) -> Result<(), KmacError> {
        if rate == 0 || rate > MAX_RATE {
            return Err(KmacError::MessageTooLong);
        }
        if self.used() != 0 {
            self.flush()?;
        }
        let remainder = self
            .emitted()
            .checked_rem(rate)
            .ok_or(KmacError::MessageTooLong)?;
        if remainder != 0 {
            let count = rate
                .checked_sub(remainder)
                .ok_or(KmacError::MessageTooLong)?;
            let zeros = [0_u8; MAX_RATE];
            let padding = zeros.get(..count).ok_or(KmacError::MessageTooLong)?;
            self.push_bytes(padding)?;
        }
        Ok(())
    }

    fn finish_bits(self) -> Option<SecretTail> {
        if self.used() == 0 {
            None
        } else {
            self.pending
                .first()
                .copied()
                .map(|byte| SecretTail::new(byte, self.used()))
        }
    }

    fn flush(&mut self) -> Result<(), KmacError> {
        self.state.update(&self.pending).map_err(KmacError::from)?;
        let emitted = self
            .emitted()
            .checked_add(1)
            .ok_or(KmacError::MessageTooLong)?;
        self.set_emitted(emitted);
        let _ = clear_owned_region(&mut self.pending);
        let _ = clear_owned_region(&mut self.used);
        Ok(())
    }

    fn used(&self) -> u8 {
        self.used.first().copied().unwrap_or_default()
    }

    fn set_used(&mut self, value: u8) {
        if let Some(used) = self.used.first_mut() {
            *used = value;
        }
    }

    fn emitted(&self) -> usize {
        usize::from_le_bytes(self.emitted)
    }

    fn set_emitted(&mut self, value: usize) {
        self.emitted.copy_from_slice(&value.to_le_bytes());
    }
}

impl<S: CshakeState> Drop for SecretPacker<'_, S> {
    fn drop(&mut self) {
        let _ = clear_owned_region(&mut self.pending);
        let _ = clear_owned_region(&mut self.used);
        let _ = clear_owned_region(&mut self.emitted);
    }
}

struct SecretTail {
    byte: [u8; 1],
    valid: [u8; 1],
}

impl SecretTail {
    const fn new(byte: u8, valid: u8) -> Self {
        Self {
            byte: [byte],
            valid: [valid],
        }
    }

    const fn as_bytes(&self) -> &[u8] {
        &self.byte
    }

    fn valid(&self) -> u8 {
        self.valid.first().copied().unwrap_or_default()
    }
}

impl Drop for SecretTail {
    fn drop(&mut self) {
        let _ = clear_owned_region(&mut self.byte);
        let _ = clear_owned_region(&mut self.valid);
    }
}

#[cfg(test)]
mod tests {
    use super::SecretEncodedInteger;
    use crate::KmacError;

    #[test]
    fn corrupt_encoded_width_fails_closed() {
        let encoded = SecretEncodedInteger {
            bytes: [0xa5; 17],
            length: [18],
        };
        assert_eq!(encoded.as_bytes(), Err(KmacError::SecretMemory));
    }
}
