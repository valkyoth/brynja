use crate::compress64::compress;

const BLOCK_BYTES: usize = 128;
const LENGTH_FIELD_BYTES: usize = 16;
const FINAL_BLOCK_PREFIX_BYTES: usize = BLOCK_BYTES - LENGTH_FIELD_BYTES;

pub(crate) const MAX_MESSAGE_BYTES: u128 = u128::MAX / 8;

pub(crate) struct Sha512State {
    state: [u64; 8],
    buffer: [u8; BLOCK_BYTES],
    buffer_len: usize,
    message_bytes: u128,
}

impl Sha512State {
    pub(crate) const fn new(initial_state: [u64; 8]) -> Self {
        Self {
            state: initial_state,
            buffer: [0; BLOCK_BYTES],
            buffer_len: 0,
            message_bytes: 0,
        }
    }

    pub(crate) const fn message_bytes(&self) -> u128 {
        self.message_bytes
    }

    pub(crate) fn check_additional_bytes(
        &self,
        additional_bytes: u128,
    ) -> Result<(), MessageTooLong> {
        checked_message_length(self.message_bytes, additional_bytes).map(|_| ())
    }

    pub(crate) fn update(&mut self, input: &[u8]) -> Result<(), MessageTooLong> {
        let additional = input.len() as u128;
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

    pub(crate) fn finalize(mut self) -> [u64; 8] {
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
        self.state
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MessageTooLong;

pub(crate) fn checked_message_length(
    current: u128,
    additional: u128,
) -> Result<u128, MessageTooLong> {
    current
        .checked_add(additional)
        .filter(|length| *length <= MAX_MESSAGE_BYTES)
        .ok_or(MessageTooLong)
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
    use super::{MAX_MESSAGE_BYTES, Sha512State};

    #[test]
    fn rejected_update_preserves_every_shared_owned_field() {
        let mut state = Sha512State::new([0x55aa; 8]);
        assert_eq!(state.update(b"retained prefix"), Ok(()));
        state.message_bytes = MAX_MESSAGE_BYTES;
        let expected_state = state.state;
        let expected_buffer = state.buffer;
        let expected_buffer_len = state.buffer_len;
        let expected_message_bytes = state.message_bytes;

        assert!(state.update(b"x").is_err());
        assert_eq!(state.state, expected_state);
        assert_eq!(state.buffer, expected_buffer);
        assert_eq!(state.buffer_len, expected_buffer_len);
        assert_eq!(state.message_bytes, expected_message_bytes);
    }
}
