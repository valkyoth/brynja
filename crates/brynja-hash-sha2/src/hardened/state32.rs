use brynja_core::clear_owned_region;

use crate::{BitString, bit_input};

use super::{
    compress32,
    owner::{FINALIZING, HardenedSha2Owner},
};

const BLOCK_BYTES: usize = 64;
const LENGTH_START: usize = 56;
const MAX_BYTES: u64 = u64::MAX / 8;

impl HardenedSha2Owner {
    pub(crate) fn message_bytes32(&self) -> u64 {
        read_length(&self.message_length)
    }

    pub(crate) fn check_bytes32(&self, additional: u64) -> Result<(), ()> {
        self.message_bytes32()
            .checked_add(additional)
            .filter(|length| *length <= MAX_BYTES)
            .map(|_| ())
            .ok_or(())
    }

    pub(crate) fn check_bits32(&self, additional: u64) -> Result<(), ()> {
        bit_input::checked_bit_length_u64(self.message_bytes32(), additional).map(|_| ())
    }

    pub(crate) fn update32(&mut self, input: &[u8]) -> Result<(), ()> {
        let additional = u64::try_from(input.len()).map_err(|_| ())?;
        let new_length = self
            .message_bytes32()
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
                brynja_core::copy_secret_region(destination, source).map_err(|_| ())?;
            }
            remaining = remaining.get(copied..).unwrap_or_default();
            self.set_buffer_len(end)?;
            if end == BLOCK_BYTES {
                if let (Some(destination), Some(source)) = (
                    self.block_copy.get_mut(..BLOCK_BYTES),
                    self.partial_input.get(..BLOCK_BYTES),
                ) {
                    brynja_core::copy_secret_region(destination, source).map_err(|_| ())?;
                }
                compress32::compress(self);
                self.wipe_compression_scratch();
                let _ = clear_owned_region(&mut self.partial_input);
                self.set_buffer_len(0)?;
            } else {
                write_length(&mut self.message_length, new_length);
                return Ok(());
            }
        }
        let mut blocks = remaining.chunks_exact(BLOCK_BYTES);
        for block in blocks.by_ref() {
            if let Some(destination) = self.block_copy.get_mut(..BLOCK_BYTES) {
                brynja_core::copy_secret_region(destination, block).map_err(|_| ())?;
            }
            compress32::compress(self);
            self.wipe_compression_scratch();
        }
        let tail = blocks.remainder();
        if let Some(destination) = self.partial_input.get_mut(..tail.len()) {
            brynja_core::copy_secret_region(destination, tail).map_err(|_| ())?;
        }
        self.set_buffer_len(tail.len())?;
        write_length(&mut self.message_length, new_length);
        Ok(())
    }

    pub(crate) fn finalize32(
        &mut self,
        partial: Option<(&u8, u8)>,
        message_bits: u64,
        output_bytes: usize,
    ) {
        self.phase[0] = FINALIZING;
        let buffered = self.buffer_len();
        if let (Some(destination), Some(source)) = (
            self.padding_block.get_mut(..buffered),
            self.partial_input.get(..buffered),
        ) {
            let _ = brynja_core::copy_secret_region(destination, source);
        }
        if let Some(target) = self.padding_block.get_mut(buffered) {
            match partial {
                Some((byte, valid_bits)) => {
                    // Equal one-byte regions; this transfer cannot reject length.
                    let _ = brynja_core::copy_secret_region(
                        core::slice::from_mut(target),
                        core::slice::from_ref(byte),
                    );
                    brynja_core::apply_secret_byte_mask(target, 0xff, 0x80 >> valid_bits);
                }
                None => *target = 0x80,
            }
        }
        if buffered >= LENGTH_START {
            self.compress_padding32();
            if let Some(block) = self.padding_block.get_mut(..BLOCK_BYTES) {
                block.fill(0);
            }
        }
        if let Some(length) = self.padding_block.get_mut(LENGTH_START..BLOCK_BYTES) {
            length.copy_from_slice(&message_bits.to_be_bytes());
        }
        self.compress_padding32();
        render32(self, output_bytes);
        let _ = clear_owned_region(&mut self.partial_input);
    }

    fn compress_padding32(&mut self) {
        if let (Some(destination), Some(source)) = (
            self.block_copy.get_mut(..BLOCK_BYTES),
            self.padding_block.get(..BLOCK_BYTES),
        ) {
            let _ = brynja_core::copy_secret_region(destination, source);
        }
        compress32::compress(self);
        self.wipe_compression_scratch();
    }
}

pub(crate) fn finalize_bits_length32(
    owner: &HardenedSha2Owner,
    input: BitString<'_>,
) -> Result<u64, ()> {
    let additional = u64::try_from(input.bit_len()).map_err(|_| ())?;
    bit_input::checked_bit_length_u64(owner.message_bytes32(), additional)
}

fn render32(owner: &mut HardenedSha2Owner, output_bytes: usize) {
    for index in 0_usize..8 {
        let start = index.saturating_mul(4);
        let Some(state) = owner.chaining_state.get(start..start.saturating_add(4)) else {
            return;
        };
        let Some(output) = owner.output_staging.get_mut(start..start.saturating_add(4)) else {
            return;
        };
        // Equal word-sized slices; the checked ranges establish exact length.
        let _ = brynja_core::copy_secret_region(output, state);
    }
    if let Some(remainder) = owner.output_staging.get_mut(output_bytes..) {
        remainder.fill(0);
    }
}

fn read_length(bytes: &[u8; 16]) -> u64 {
    let Some(prefix) = bytes.get(..8) else {
        return 0;
    };
    let Ok(value) = <[u8; 8]>::try_from(prefix) else {
        return 0;
    };
    u64::from_be_bytes(value)
}

fn write_length(bytes: &mut [u8; 16], value: u64) {
    bytes.fill(0);
    if let Some(prefix) = bytes.get_mut(..8) {
        prefix.copy_from_slice(&value.to_be_bytes());
    }
}
