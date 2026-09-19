use brynja_core::clear_owned_region;
use brynja_hash_sha3::{Fips202BitString, left_encode_u128, right_encode_u128};

use crate::{backend::CshakeState, error::KmacError};

const MAX_RATE: usize = 168;

/// Private absorb port shared by portable and capability-bound hardened owners.
pub(crate) trait Absorb {
    fn absorb(&mut self, input: &[u8]) -> Result<(), KmacError>;
}

impl<S: CshakeState> Absorb for S {
    fn absorb(&mut self, input: &[u8]) -> Result<(), KmacError> {
        self.update(input).map_err(KmacError::from)
    }
}

pub(crate) fn absorb_key<S: Absorb>(
    state: &mut S,
    key: Fips202BitString<'_>,
    rate: usize,
) -> Result<(), KmacError> {
    let key_bits = u128::try_from(key.bit_len()).map_err(|_| KmacError::MessageTooLong)?;
    let rate_value = u128::try_from(rate).map_err(|_| KmacError::MessageTooLong)?;
    let mut storage = Framing::new();
    let mut packer = SecretPacker::new(state, &mut storage);
    packer.push_bytes(left_encode_u128(rate_value).as_bytes())?;
    let mut key_length = SecretEncodedInteger::new();
    key_length.left_encode(key_bits)?;
    packer.push_bytes(key_length.as_bytes()?)?;
    packer.push_bit_string(key)?;
    packer.finish_bytepad(rate)
}

struct SecretEncodedInteger {
    bytes: [u8; 17],
    length: [u8; 1],
}

impl SecretEncodedInteger {
    const fn new() -> Self {
        Self {
            bytes: [0; 17],
            length: [0],
        }
    }

    fn left_encode(&mut self, value: u128) -> Result<(), KmacError> {
        self.wipe();
        let mut remaining = value;
        let mut width = 1_u8;
        while remaining > u128::from(u8::MAX) {
            width = width.checked_add(1).ok_or(KmacError::MessageTooLong)?;
            remaining >>= 8;
        }
        let total = width.checked_add(1).ok_or(KmacError::MessageTooLong)?;
        self.length = [total];
        let Some(prefix) = self.bytes.first_mut() else {
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
            let Some(target) = self.bytes.get_mut(position) else {
                return Err(KmacError::SecretMemory);
            };
            *target = byte;
        }
        Ok(())
    }

    fn as_bytes(&self) -> Result<&[u8], KmacError> {
        let length = usize::from(self.length.first().copied().unwrap_or_default());
        self.bytes.get(..length).ok_or(KmacError::SecretMemory)
    }

    fn wipe(&mut self) {
        let _ = clear_owned_region(&mut self.bytes);
        let _ = clear_owned_region(&mut self.length);
    }
}

impl Drop for SecretEncodedInteger {
    fn drop(&mut self) {
        self.wipe();
    }
}

pub(crate) fn append_right_encode<S: CshakeState>(
    state: &mut S,
    final_message: Option<Fips202BitString<'_>>,
    output_bits: u128,
) -> Result<S::Reader, KmacError> {
    append_suffix(state, final_message, output_bits, |state, input| {
        if !input.as_bytes().is_empty() {
            state
                .finalize_bits_xof_erasing_source(input)
                .map_err(KmacError::from)
        } else {
            state.finalize_xof_erasing_source().map_err(KmacError::from)
        }
    })
}

pub(crate) fn append_suffix<S: Absorb, R>(
    state: &mut S,
    final_message: Option<Fips202BitString<'_>>,
    output_bits: u128,
    finish: impl FnOnce(&mut S, Fips202BitString<'_>) -> Result<R, KmacError>,
) -> Result<R, KmacError> {
    // A fresh packer bulk-absorbs the entire complete-byte message prefix.
    // Only right_encode (at most 17 bytes for u128) follows a partial byte.
    // Do not flush to alignment here: that would insert bits into the message.
    let mut storage = Framing::new();
    let mut packer = SecretPacker::new(state, &mut storage);
    if let Some(message) = final_message {
        packer.push_bit_string(message)?;
    }
    packer.push_bytes(right_encode_u128(output_bits).as_bytes())?;
    packer.finish_bits(finish)
}

struct Framing {
    pending: [u8; 1],
    used: [u8; 1],
    emitted: [u8; core::mem::size_of::<usize>()],
}
impl Framing {
    const fn new() -> Self {
        Self {
            pending: [0],
            used: [0],
            emitted: [0; core::mem::size_of::<usize>()],
        }
    }
    fn wipe(&mut self) {
        let _ = clear_owned_region(&mut self.pending);
        let _ = clear_owned_region(&mut self.used);
        let _ = clear_owned_region(&mut self.emitted);
    }
}
impl Drop for Framing {
    fn drop(&mut self) {
        self.wipe();
    }
}

// The frame is allocated before accepting secret input. Finalizers borrow its
// partial byte directly; neither finalization nor bytepad consumes the storage.
struct SecretPacker<'state, 'storage, S: Absorb> {
    state: &'state mut S,
    storage: &'storage mut Framing,
}

impl<'state, 'storage, S: Absorb> SecretPacker<'state, 'storage, S> {
    fn new(state: &'state mut S, storage: &'storage mut Framing) -> Self {
        storage.wipe();
        Self { state, storage }
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
        let tail = input.as_bytes().last().ok_or(KmacError::InvalidBitString)?;
        self.push_bits(tail, input.valid_bits_in_last_byte())
    }

    fn push_bytes(&mut self, input: &[u8]) -> Result<(), KmacError> {
        if self.used() == 0 {
            self.state.absorb(input)?;
            let emitted = self
                .emitted()
                .checked_add(input.len())
                .ok_or(KmacError::MessageTooLong)?;
            self.set_emitted(emitted);
            return Ok(());
        }
        for byte in input {
            self.push_bits(byte, 8)?;
        }
        Ok(())
    }

    fn push_bits(&mut self, byte: &u8, valid: u8) -> Result<(), KmacError> {
        if valid > 8 || self.used() >= 8 {
            return Err(KmacError::InvalidBitString);
        }
        let mut position = 0_u8;
        while position < valid {
            let used = self.used();
            let capacity = 8_u8.checked_sub(used).ok_or(KmacError::InvalidBitString)?;
            let remaining = valid
                .checked_sub(position)
                .ok_or(KmacError::InvalidBitString)?;
            let take = core::cmp::min(capacity, remaining);
            let pending = self
                .storage
                .pending
                .first_mut()
                .ok_or(KmacError::InvalidBitString)?;
            // Only unused (zero) pending bits are filled, so XOR is insertion.
            // Keep the source byte borrowed across both possible fragments.
            brynja_core::xor_secret_byte_bits(pending, byte, position, take, used)
                .map_err(|_| KmacError::InvalidBitString)?;
            self.set_used(used.checked_add(take).ok_or(KmacError::MessageTooLong)?);
            position = position
                .checked_add(take)
                .ok_or(KmacError::MessageTooLong)?;
            if self.used() == 8 {
                self.flush()?;
            }
        }
        Ok(())
    }

    fn finish_bytepad(&mut self, rate: usize) -> Result<(), KmacError> {
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

    fn finish_bits<R>(
        &mut self,
        finish: impl FnOnce(&mut S, Fips202BitString<'_>) -> Result<R, KmacError>,
    ) -> Result<R, KmacError> {
        let bytes = if self.used() == 0 {
            &[][..]
        } else {
            &self.storage.pending[..]
        };
        let input =
            Fips202BitString::new(bytes, self.used()).map_err(|_| KmacError::InvalidBitString)?;
        finish(self.state, input)
    }

    fn flush(&mut self) -> Result<(), KmacError> {
        self.state.absorb(&self.storage.pending)?;
        let emitted = self
            .emitted()
            .checked_add(1)
            .ok_or(KmacError::MessageTooLong)?;
        self.set_emitted(emitted);
        let _ = clear_owned_region(&mut self.storage.pending);
        let _ = clear_owned_region(&mut self.storage.used);
        Ok(())
    }

    fn used(&self) -> u8 {
        self.storage.used.first().copied().unwrap_or_default()
    }

    fn set_used(&mut self, value: u8) {
        if let Some(used) = self.storage.used.first_mut() {
            *used = value;
        }
    }

    fn emitted(&self) -> usize {
        usize::from_le_bytes(self.storage.emitted)
    }

    fn set_emitted(&mut self, value: usize) {
        self.storage.emitted.copy_from_slice(&value.to_le_bytes());
    }
}

impl<S: Absorb> Drop for SecretPacker<'_, '_, S> {
    fn drop(&mut self) {
        self.storage.wipe();
    }
}

#[cfg(test)]
mod framing_tests;

#[cfg(test)]
mod tests {
    use super::{Absorb, SecretEncodedInteger, absorb_key, append_suffix};
    use crate::KmacError;
    use brynja_hash_sha3::{Fips202BitString, right_encode_u128};

    #[derive(Default)]
    struct AbsorbCalls {
        lengths: [usize; 32],
        count: usize,
    }
    impl Absorb for AbsorbCalls {
        fn absorb(&mut self, input: &[u8]) -> Result<(), KmacError> {
            let slot = self
                .lengths
                .get_mut(self.count)
                .ok_or(KmacError::MessageTooLong)?;
            *slot = input.len();
            self.count = self.count.checked_add(1).ok_or(KmacError::MessageTooLong)?;
            Ok(())
        }
    }

    #[test]
    fn large_final_chunks_keep_bulk_absorption() -> Result<(), KmacError> {
        let bytes = [0_u8; 4097];
        for size in [1, 168, 4097] {
            for valid in 1..=8 {
                for bits in [0, 255, 256, u128::MAX] {
                    let prefix = bytes.get(..size).ok_or(KmacError::MessageTooLong)?;
                    let input = Fips202BitString::new(prefix, valid)
                        .map_err(|_| KmacError::InvalidBitString)?;
                    let mut calls = AbsorbCalls::default();
                    let tail = append_suffix(&mut calls, Some(input), bits, |_, tail| {
                        Ok(tail.valid_bits_in_last_byte())
                    })?;
                    let trailer = right_encode_u128(bits);
                    if valid == 8 {
                        assert_eq!(calls.count, 2);
                        assert_eq!(&calls.lengths[..2], &[size, trailer.as_bytes().len()]);
                        assert_eq!(tail, 0);
                    } else {
                        assert_eq!(calls.lengths[0], size - 1);
                        assert_eq!(calls.count, 1 + trailer.as_bytes().len());
                        assert!(calls.count <= 18);
                        let singles = calls
                            .lengths
                            .get(1..calls.count)
                            .ok_or(KmacError::MessageTooLong)?;
                        assert!(singles.iter().all(|n| *n == 1));
                        assert_eq!(tail, valid);
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn large_partial_keys_keep_bulk_absorption() -> Result<(), KmacError> {
        let bytes = [0_u8; 4097];
        for rate in [136, 168] {
            for valid in 1..=8 {
                let key = Fips202BitString::new(&bytes, valid)
                    .map_err(|_| KmacError::InvalidBitString)?;
                let mut calls = AbsorbCalls::default();
                absorb_key(&mut calls, key, rate)?;
                assert_eq!(calls.lengths[2], if valid == 8 { 4097 } else { 4096 });
                assert!(calls.count <= 5);
                let emitted = calls
                    .lengths
                    .get(..calls.count)
                    .ok_or(KmacError::MessageTooLong)?;
                assert_eq!(emitted.iter().sum::<usize>() % rate, 0);
            }
        }
        Ok(())
    }

    #[test]
    fn corrupt_encoded_width_fails_closed() {
        let encoded = SecretEncodedInteger {
            bytes: [0xa5; 17],
            length: [18],
        };
        assert_eq!(encoded.as_bytes(), Err(KmacError::SecretMemory));
    }
}
