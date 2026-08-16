use brynja_hash_core::{FixedOutput, Update};

use crate::{Sha224Digest, Sha224Error, compress::compress};

const BLOCK_BYTES: usize = 64;
const FINAL_BLOCK_PREFIX_BYTES: usize = 56;
const INITIAL_STATE: [u32; 8] = [
    0xc105_9ed8,
    0x367c_d507,
    0x3070_dd17,
    0xf70e_5939,
    0xffc0_0b31,
    0x6858_1511,
    0x64f9_8fa7,
    0xbefa_4fa4,
];

/// Portable streaming SHA-224 state.
///
/// Finalization consumes the state. This type intentionally does not implement
/// `Clone`, `Copy`, `Debug`, or formatting traits. Its ordinary unkeyed state
/// is not promised to be erased after use; secret-bearing constructions need a
/// separate hardened owner.
pub struct Sha224 {
    state: [u32; 8],
    buffer: [u8; BLOCK_BYTES],
    buffer_len: usize,
    message_bytes: u64,
}

impl Sha224 {
    /// Maximum byte-oriented message length admitted by FIPS 180-4.
    pub const MAX_MESSAGE_BYTES: u64 = u64::MAX / 8;

    /// Creates an empty portable SHA-224 state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: INITIAL_STATE,
            buffer: [0; BLOCK_BYTES],
            buffer_len: 0,
            message_bytes: 0,
        }
    }

    /// Returns the number of message bytes accepted so far.
    #[must_use]
    pub const fn message_bytes(&self) -> u64 {
        self.message_bytes
    }

    /// Checks an update length without changing this state.
    pub fn check_additional_bytes(&self, additional_bytes: u64) -> Result<(), Sha224Error> {
        checked_message_length(self.message_bytes, additional_bytes).map(|_| ())
    }

    /// Absorbs all input or rejects it before changing observable state.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Sha224Error> {
        let additional = u64::try_from(input.len()).map_err(|_| Sha224Error::MessageTooLong)?;
        let new_length = checked_message_length(self.message_bytes, additional)?;
        let mut input = input.iter();

        if self.buffer_len != 0 {
            let needed = BLOCK_BYTES.saturating_sub(self.buffer_len);
            let mut copied = 0_usize;
            for (slot, byte) in self
                .buffer
                .iter_mut()
                .skip(self.buffer_len)
                .take(needed)
                .zip(input.by_ref())
            {
                *slot = *byte;
                copied = copied.saturating_add(1);
            }
            self.buffer_len = self.buffer_len.saturating_add(copied);
            if self.buffer_len == BLOCK_BYTES {
                compress(&mut self.state, &self.buffer);
                self.buffer.fill(0);
                self.buffer_len = 0;
            } else {
                self.message_bytes = new_length;
                return Ok(());
            }
        }

        let mut blocks = input.as_slice().chunks_exact(BLOCK_BYTES);
        for bytes in blocks.by_ref() {
            let mut block = [0_u8; BLOCK_BYTES];
            for (target, byte) in block.iter_mut().zip(bytes.iter()) {
                *target = *byte;
            }
            compress(&mut self.state, &block);
        }
        let remainder = blocks.remainder();
        for (target, byte) in self.buffer.iter_mut().zip(remainder.iter()) {
            *target = *byte;
        }
        self.buffer_len = remainder.len();
        self.message_bytes = new_length;
        Ok(())
    }

    /// Consumes the state and returns the exact SHA-224 digest.
    #[must_use]
    pub fn finalize(mut self) -> Sha224Digest {
        if let Some(marker) = self.buffer.get_mut(self.buffer_len) {
            *marker = 0x80;
        }
        let after_marker = self.buffer_len.saturating_add(1);
        for byte in self.buffer.iter_mut().skip(after_marker) {
            *byte = 0;
        }
        if padding_block_count(self.buffer_len) == 2 {
            compress(&mut self.state, &self.buffer);
            self.buffer.fill(0);
        }
        let message_bits = self.message_bytes.saturating_mul(8);
        for (target, byte) in self
            .buffer
            .iter_mut()
            .skip(FINAL_BLOCK_PREFIX_BYTES)
            .zip(message_bits.to_be_bytes())
        {
            *target = byte;
        }
        compress(&mut self.state, &self.buffer);

        let mut output = [0_u8; Sha224Digest::LENGTH];
        for (bytes, word) in output.chunks_exact_mut(4).zip(self.state.iter()) {
            if let [first, second, third, fourth] = bytes {
                [*first, *second, *third, *fourth] = word.to_be_bytes();
            }
        }
        Sha224Digest::from_bytes(output)
    }
}

impl Default for Sha224 {
    fn default() -> Self {
        Self::new()
    }
}

impl Update for Sha224 {
    type Error = Sha224Error;

    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        Self::update(self, input)
    }
}

impl FixedOutput for Sha224 {
    type Output = Sha224Digest;

    fn finalize(self) -> Self::Output {
        Self::finalize(self)
    }
}

pub(crate) fn checked_message_length(current: u64, additional: u64) -> Result<u64, Sha224Error> {
    current
        .checked_add(additional)
        .filter(|length| *length <= Sha224::MAX_MESSAGE_BYTES)
        .ok_or(Sha224Error::MessageTooLong)
}

pub(crate) const fn padding_block_count(buffer_len: usize) -> usize {
    if buffer_len < FINAL_BLOCK_PREFIX_BYTES {
        1
    } else {
        2
    }
}

#[cfg(test)]
mod tests {
    use super::{Sha224, Sha224Error};

    #[test]
    fn rejected_update_preserves_every_owned_field() {
        let mut state = Sha224::new();
        assert_eq!(state.update(b"retained prefix"), Ok(()));
        state.message_bytes = Sha224::MAX_MESSAGE_BYTES;
        let expected_state = state.state;
        let expected_buffer = state.buffer;
        let expected_buffer_len = state.buffer_len;
        let expected_message_bytes = state.message_bytes;

        assert_eq!(state.update(b"x"), Err(Sha224Error::MessageTooLong));
        assert_eq!(state.state, expected_state);
        assert_eq!(state.buffer, expected_buffer);
        assert_eq!(state.buffer_len, expected_buffer_len);
        assert_eq!(state.message_bytes, expected_message_bytes);
    }
}
