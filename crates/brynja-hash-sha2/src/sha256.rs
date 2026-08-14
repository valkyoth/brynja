use brynja_hash_core::{FixedOutput, Update};

use crate::{Sha256Digest, Sha256Error, compress::compress};

const BLOCK_BYTES: usize = 64;
const LENGTH_FIELD_BYTES: usize = 8;
const FINAL_BLOCK_PREFIX_BYTES: usize = BLOCK_BYTES - LENGTH_FIELD_BYTES;
const INITIAL_STATE: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// Portable streaming SHA-256 state.
///
/// Finalization consumes the state. This type intentionally does not implement
/// `Clone`, `Copy`, `Debug`, or formatting traits. SHA-256 accepts byte strings
/// whose bit length is less than 2^64.
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; BLOCK_BYTES],
    buffer_len: usize,
    message_bytes: u64,
}

impl Sha256 {
    /// Maximum byte-oriented message length admitted by FIPS 180-4.
    pub const MAX_MESSAGE_BYTES: u64 = u64::MAX / 8;

    /// Creates an empty portable SHA-256 state.
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

    /// Absorbs all input or rejects it before changing the state.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Sha256Error> {
        let additional = u64::try_from(input.len()).map_err(|_| Sha256Error::MessageTooLong)?;
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

    /// Consumes the state and returns the exact SHA-256 digest.
    #[must_use]
    pub fn finalize(mut self) -> Sha256Digest {
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

        let mut output = [0_u8; Sha256Digest::LENGTH];
        for (bytes, word) in output.chunks_exact_mut(4).zip(self.state.iter()) {
            if let [first, second, third, fourth] = bytes {
                [*first, *second, *third, *fourth] = word.to_be_bytes();
            }
        }
        Sha256Digest::from_bytes(output)
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Update for Sha256 {
    type Error = Sha256Error;

    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        Self::update(self, input)
    }
}

impl FixedOutput for Sha256 {
    type Output = Sha256Digest;

    fn finalize(self) -> Self::Output {
        Self::finalize(self)
    }
}

pub(crate) fn checked_message_length(current: u64, additional: u64) -> Result<u64, Sha256Error> {
    current
        .checked_add(additional)
        .filter(|length| *length <= Sha256::MAX_MESSAGE_BYTES)
        .ok_or(Sha256Error::MessageTooLong)
}

pub(crate) const fn padding_block_count(buffer_len: usize) -> usize {
    if buffer_len < FINAL_BLOCK_PREFIX_BYTES {
        1
    } else {
        2
    }
}
