use brynja_core::clear_owned_region;

use crate::{BitString, bit_input};

use super::{
    compress64,
    owner::{FINALIZING, HardenedSha2Owner},
};

const BLOCK_BYTES: usize = 128;
const LENGTH_START: usize = 112;
const MAX_BYTES: u128 = u128::MAX / 8;

impl HardenedSha2Owner {
    pub(crate) fn message_bytes64(&self) -> u128 {
        u128::from_be_bytes(self.message_length)
    }

    pub(crate) fn check_bytes64(&self, additional: u128) -> Result<(), ()> {
        self.message_bytes64()
            .checked_add(additional)
            .filter(|length| *length <= MAX_BYTES)
            .map(|_| ())
            .ok_or(())
    }

    pub(crate) fn check_bits64(&self, additional: u128) -> Result<(), ()> {
        bit_input::checked_bit_length_u128(self.message_bytes64(), additional).map(|_| ())
    }

    pub(crate) fn update64(&mut self, input: &[u8]) -> Result<(), ()> {
        let additional = input.len() as u128;
        let new_length = self
            .message_bytes64()
            .checked_add(additional)
            .filter(|length| *length <= MAX_BYTES)
            .ok_or(())?;
        let mut remaining = input;
        let buffered = self.buffer_len();
        if buffered != 0 {
            let copied = core::cmp::min(BLOCK_BYTES.saturating_sub(buffered), remaining.len());
            let end = buffered.saturating_add(copied);
            if let (Some(destination), Some(source)) = (
                self.partial_input.get_mut(buffered..end),
                remaining.get(..copied),
            ) {
                destination.copy_from_slice(source);
            }
            remaining = remaining.get(copied..).unwrap_or_default();
            self.set_buffer_len(end);
            if end == BLOCK_BYTES {
                self.block_copy.copy_from_slice(&self.partial_input);
                compress64::compress(self);
                self.wipe_compression_scratch();
                let _ = clear_owned_region(&mut self.partial_input);
                self.set_buffer_len(0);
            } else {
                self.message_length = new_length.to_be_bytes();
                return Ok(());
            }
        }
        let mut blocks = remaining.chunks_exact(BLOCK_BYTES);
        for block in blocks.by_ref() {
            self.block_copy.copy_from_slice(block);
            compress64::compress(self);
            self.wipe_compression_scratch();
        }
        let tail = blocks.remainder();
        if let Some(destination) = self.partial_input.get_mut(..tail.len()) {
            destination.copy_from_slice(tail);
        }
        self.set_buffer_len(tail.len());
        self.message_length = new_length.to_be_bytes();
        Ok(())
    }

    pub(crate) fn finalize64(
        &mut self,
        partial: Option<(u8, u8)>,
        message_bits: u128,
        output_bytes: usize,
    ) {
        self.phase[0] = FINALIZING;
        let buffered = self.buffer_len();
        if let (Some(destination), Some(source)) = (
            self.padding_block.get_mut(..buffered),
            self.partial_input.get(..buffered),
        ) {
            destination.copy_from_slice(source);
        }
        let marker = match partial {
            Some((byte, valid_bits)) => byte | (0x80_u8 >> valid_bits),
            None => 0x80,
        };
        if let Some(target) = self.padding_block.get_mut(buffered) {
            *target = marker;
        }
        if buffered >= LENGTH_START {
            self.compress_padding64();
            self.padding_block.fill(0);
        }
        if let Some(length) = self.padding_block.get_mut(LENGTH_START..) {
            length.copy_from_slice(&message_bits.to_be_bytes());
        }
        self.compress_padding64();
        render64(self, output_bytes);
        let _ = clear_owned_region(&mut self.partial_input);
    }

    fn compress_padding64(&mut self) {
        self.block_copy.copy_from_slice(&self.padding_block);
        compress64::compress(self);
        self.wipe_compression_scratch();
    }
}

pub(crate) fn finalize_bits_length64(
    owner: &HardenedSha2Owner,
    input: BitString<'_>,
) -> Result<u128, ()> {
    let additional = u128::try_from(input.bit_len()).map_err(|_| ())?;
    bit_input::checked_bit_length_u128(owner.message_bytes64(), additional)
}

fn render64(owner: &mut HardenedSha2Owner, output_bytes: usize) {
    for index in 0_usize..8 {
        let start = index.saturating_mul(8);
        let Some(state) = owner.chaining_state.get(start..start.saturating_add(8)) else {
            return;
        };
        let Some(output) = owner.output_staging.get_mut(start..start.saturating_add(8)) else {
            return;
        };
        output.copy_from_slice(state);
    }
    if let Some(remainder) = owner.output_staging.get_mut(output_bytes..) {
        remainder.fill(0);
    }
}
