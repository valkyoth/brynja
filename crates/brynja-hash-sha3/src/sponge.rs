use crate::keccak::{byte, permute, xor_byte};

pub(super) const MAX_RATE_BYTES: usize = 144;
pub(super) const SHA3_SUFFIX: u8 = 0x06;

pub(super) struct Sponge<const RATE: usize> {
    state: [u64; 25],
    buffer: [u8; MAX_RATE_BYTES],
    buffer_len: usize,
    message_bytes: u128,
}

impl<const RATE: usize> Sponge<RATE> {
    pub(super) const MAX_MESSAGE_BYTES: u128 = u128::MAX;

    pub(super) const fn new() -> Self {
        Self {
            state: [0; 25],
            buffer: [0; MAX_RATE_BYTES],
            buffer_len: 0,
            message_bytes: 0,
        }
    }

    pub(super) const fn message_bytes(&self) -> u128 {
        self.message_bytes
    }

    pub(super) fn check_additional_bytes(&self, additional: u128) -> Result<(), ()> {
        checked_message_length(self.message_bytes, additional).map(|_| ())
    }

    pub(super) fn update(&mut self, input: &[u8]) -> Result<(), ()> {
        let additional = u128::try_from(input.len()).map_err(|_| ())?;
        let new_length = checked_message_length(self.message_bytes, additional)?;
        let mut remaining = input.iter();

        if self.buffer_len != 0 {
            let needed = RATE.saturating_sub(self.buffer_len);
            let mut copied = 0_usize;
            for (target, source) in self
                .buffer
                .iter_mut()
                .skip(self.buffer_len)
                .take(needed)
                .zip(remaining.by_ref())
            {
                *target = *source;
                copied = copied.saturating_add(1);
            }
            self.buffer_len = self.buffer_len.saturating_add(copied);
            if self.buffer_len == RATE {
                absorb(&mut self.state, &self.buffer, RATE);
                self.buffer.fill(0);
                self.buffer_len = 0;
            } else {
                self.message_bytes = new_length;
                return Ok(());
            }
        }

        let mut blocks = remaining.as_slice().chunks_exact(RATE);
        for block in blocks.by_ref() {
            absorb(&mut self.state, block, RATE);
        }
        let remainder = blocks.remainder();
        for (target, source) in self.buffer.iter_mut().zip(remainder) {
            *target = *source;
        }
        self.buffer_len = remainder.len();
        self.message_bytes = new_length;
        Ok(())
    }

    pub(super) fn finalize<const OUTPUT: usize>(mut self) -> [u8; OUTPUT] {
        if let Some(marker) = self.buffer.get_mut(self.buffer_len) {
            *marker ^= SHA3_SUFFIX;
        }
        if let Some(last) = self.buffer.get_mut(RATE.saturating_sub(1)) {
            *last ^= 0x80;
        }
        absorb(&mut self.state, &self.buffer, RATE);

        let mut output = [0_u8; OUTPUT];
        for (position, target) in output.iter_mut().enumerate() {
            *target = byte(&self.state, position);
        }
        output
    }
}

fn absorb(state: &mut [u64; 25], block: &[u8], rate: usize) {
    for (position, value) in block.iter().take(rate).enumerate() {
        xor_byte(state, position, *value);
    }
    permute(state);
}

pub(crate) const fn checked_message_length(current: u128, additional: u128) -> Result<u128, ()> {
    match current.checked_add(additional) {
        Some(length) => Ok(length),
        None => Err(()),
    }
}
