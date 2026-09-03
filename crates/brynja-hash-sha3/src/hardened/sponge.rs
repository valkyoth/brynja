use brynja_core::{SecretRegionInitialization, clear_owned_region};

use crate::Fips202Output;

use super::{
    output::{HardenedSha3Error, Sha3PublicDeclassification},
    owner::{HardenedFips202Owner, SQUEEZING},
    permutation,
};

pub(crate) const SHA3_SUFFIX: u8 = 0x06;
pub(crate) const SHAKE_SUFFIX: u8 = 0x1f;
pub(crate) const SHA3_SUFFIX_BITS: u8 = 3;
pub(crate) const SHAKE_SUFFIX_BITS: u8 = 5;

impl<const RATE: usize> HardenedFips202Owner<RATE> {
    pub(crate) fn message_bytes(&self) -> u128 {
        read_counter(&self.message_length)
    }

    pub(crate) fn output_bytes(&self) -> u128 {
        read_counter(&self.output_length)
    }

    pub(crate) fn cshake_message_bytes(&self) -> u128 {
        self.message_bytes()
            .saturating_sub(read_counter(&self.cshake_setup_length))
    }

    pub(crate) fn check_message_bytes(&self, additional: u128) -> Result<(), ()> {
        self.message_bytes()
            .checked_add(additional)
            .map(|_| ())
            .ok_or(())
    }

    pub(crate) fn check_message_bits(&self, additional: u128) -> Result<(), ()> {
        self.message_bytes()
            .checked_add(additional / 8)
            .map(|_| ())
            .ok_or(())
    }

    pub(crate) fn check_output_bytes(&self, additional: u128) -> Result<(), ()> {
        self.output_bytes()
            .checked_add(additional)
            .map(|_| ())
            .ok_or(())
    }

    pub(crate) fn check_output_bits(&self, additional: u128) -> Result<(), ()> {
        self.output_bytes()
            .checked_add(additional / 8)
            .map(|_| ())
            .ok_or(())
    }

    pub(crate) fn update(&mut self, input: &[u8]) -> Result<(), ()> {
        let additional = u128::try_from(input.len()).map_err(|_| ())?;
        let new_length = self.message_bytes().checked_add(additional).ok_or(())?;
        let mut remaining = input;
        let buffered = self.buffer_len();
        if buffered != 0 {
            let copied = core::cmp::min(RATE.saturating_sub(buffered), remaining.len());
            let end = buffered.saturating_add(copied);
            if let (Some(destination), Some(source)) = (
                self.partial_input.get_mut(buffered..end),
                remaining.get(..copied),
            ) {
                destination.copy_from_slice(source);
            }
            remaining = remaining.get(copied..).unwrap_or_default();
            self.set_buffer_len(end);
            if end == RATE {
                self.absorb_partial();
            } else {
                write_counter(&mut self.message_length, new_length);
                return Ok(());
            }
        }
        let mut blocks = remaining.chunks_exact(RATE);
        for block in blocks.by_ref() {
            self.absorb_slice(block);
        }
        let tail = blocks.remainder();
        if let Some(destination) = self.partial_input.get_mut(..tail.len()) {
            destination.copy_from_slice(tail);
        }
        self.set_buffer_len(tail.len());
        write_counter(&mut self.message_length, new_length);
        Ok(())
    }

    pub(crate) fn finalize(&mut self, partial: Option<(u8, u8)>, suffix: u8, suffix_bits: u8) {
        self.suffix_staging[0] = partial.map_or(0, |tail| tail.0);
        self.suffix_staging[1] = partial.map_or(0, |tail| tail.1);
        self.suffix_staging[2] = suffix;
        self.suffix_staging[3] = suffix_bits;
        let buffered = self.buffer_len();
        if let (Some(destination), Some(source)) = (
            self.padding_block.get_mut(..buffered),
            self.partial_input.get(..buffered),
        ) {
            destination.copy_from_slice(source);
        }
        let mut bit_position = buffered.saturating_mul(8);
        if let Some((byte, valid_bits)) = partial {
            if let Some(target) = self.padding_block.get_mut(buffered) {
                *target = byte & low_mask(valid_bits);
            }
            bit_position = bit_position.saturating_add(usize::from(valid_bits));
        }
        for suffix_position in 0..suffix_bits {
            if bit_position == RATE.saturating_mul(8) {
                self.absorb_padding();
                bit_position = 0;
            }
            if suffix & (1_u8 << suffix_position) != 0 {
                let byte_position = bit_position / 8;
                let bit_in_byte = bit_position % 8;
                if let Some(target) = self.padding_block.get_mut(byte_position) {
                    *target ^= 1_u8 << bit_in_byte;
                }
            }
            bit_position = bit_position.saturating_add(1);
        }
        if bit_position == RATE.saturating_mul(8) {
            self.absorb_padding();
        }
        if let Some(last) = self.padding_block.get_mut(RATE.saturating_sub(1)) {
            *last ^= 0x80;
        }
        self.absorb_padding();
        self.phase[0] = SQUEEZING;
        self.set_squeeze_position(0);
        let _ = clear_owned_region(&mut self.partial_input);
        self.set_buffer_len(0);
        self.wipe_staging();
    }

    pub(crate) fn stage_fixed(&mut self, output_bytes: usize) {
        for index in 0..output_bytes {
            if let (Some(destination), Some(source)) = (
                self.squeeze_staging.get_mut(index),
                self.sponge_lanes.get(index),
            ) {
                *destination = *source;
            }
        }
    }

    pub(crate) fn staged(&self, output_bytes: usize) -> Option<&[u8]> {
        self.squeeze_staging.get(..output_bytes)
    }

    pub(crate) fn squeeze_public(
        &mut self,
        destination: &mut [u8],
        _authority: Sha3PublicDeclassification,
    ) -> Result<(), HardenedSha3Error> {
        let additional =
            u128::try_from(destination.len()).map_err(|_| HardenedSha3Error::OutputTooLong)?;
        let new_length = self
            .output_bytes()
            .checked_add(additional)
            .ok_or(HardenedSha3Error::OutputTooLong)?;
        self.squeeze_to_slice(destination);
        write_counter(&mut self.output_length, new_length);
        Ok(())
    }

    pub(crate) fn squeeze_secret(
        &mut self,
        initialization: &mut SecretRegionInitialization<'_>,
        output_bytes: usize,
    ) -> Result<(), HardenedSha3Error> {
        let additional =
            u128::try_from(output_bytes).map_err(|_| HardenedSha3Error::OutputTooLong)?;
        let new_length = self
            .output_bytes()
            .checked_add(additional)
            .ok_or(HardenedSha3Error::OutputTooLong)?;
        let mut remaining = output_bytes;
        while remaining != 0 {
            let count = core::cmp::min(remaining, RATE);
            self.fill_staging(count);
            let staged = self
                .squeeze_staging
                .get(..count)
                .ok_or(HardenedSha3Error::OutputLength)?;
            let result = initialization
                .write(staged)
                .map_err(HardenedSha3Error::from);
            let _ = clear_owned_region(&mut self.squeeze_staging);
            result?;
            remaining = remaining.saturating_sub(count);
        }
        write_counter(&mut self.output_length, new_length);
        Ok(())
    }

    pub(crate) fn squeeze_final_bits_public(
        &mut self,
        output: Fips202Output<'_>,
        authority: Sha3PublicDeclassification,
    ) -> Result<(), HardenedSha3Error> {
        let bit_len =
            u128::try_from(output.bit_len()).map_err(|_| HardenedSha3Error::OutputTooLong)?;
        self.check_output_bits(bit_len)
            .map_err(|()| HardenedSha3Error::OutputTooLong)?;
        let (destination, valid) = output.into_parts();
        let complete = complete_output_bytes(destination.len(), valid);
        let (whole, tail) = destination.split_at_mut(complete);
        self.squeeze_public(whole, authority)?;
        if let Some(target) = tail.first_mut() {
            *target = self.next_byte() & low_mask(valid);
        }
        Ok(())
    }

    pub(crate) fn squeeze_final_bits_secret(
        &mut self,
        output_bytes: usize,
        valid: u8,
        initialization: &mut SecretRegionInitialization<'_>,
    ) -> Result<(), HardenedSha3Error> {
        let complete = complete_output_bytes(output_bytes, valid);
        let bit_len = u128::try_from(complete)
            .ok()
            .and_then(|bytes| bytes.checked_mul(8))
            .and_then(|bits| bits.checked_add(if valid == 8 { 0 } else { u128::from(valid) }))
            .ok_or(HardenedSha3Error::OutputTooLong)?;
        self.check_output_bits(bit_len)
            .map_err(|()| HardenedSha3Error::OutputTooLong)?;
        self.squeeze_secret(initialization, complete)?;
        if complete != output_bytes {
            self.fill_staging(1);
            let Some(tail) = self.squeeze_staging.first_mut() else {
                return Err(HardenedSha3Error::OutputLength);
            };
            *tail &= low_mask(valid);
            let result = initialization
                .write(&self.squeeze_staging[..1])
                .map_err(HardenedSha3Error::from);
            let _ = clear_owned_region(&mut self.squeeze_staging);
            result?;
        }
        Ok(())
    }

    fn absorb_partial(&mut self) {
        for index in 0..RATE {
            if let (Some(state), Some(input)) = (
                self.sponge_lanes.get_mut(index),
                self.partial_input.get(index),
            ) {
                *state ^= *input;
            }
        }
        permutation::permute(self);
        let _ = clear_owned_region(&mut self.partial_input);
        self.set_buffer_len(0);
    }

    fn absorb_slice(&mut self, block: &[u8]) {
        for (state, input) in self.sponge_lanes.iter_mut().take(RATE).zip(block) {
            *state ^= *input;
        }
        permutation::permute(self);
    }

    fn absorb_padding(&mut self) {
        for index in 0..RATE {
            if let (Some(state), Some(input)) = (
                self.sponge_lanes.get_mut(index),
                self.padding_block.get(index),
            ) {
                *state ^= *input;
            }
        }
        permutation::permute(self);
        let _ = clear_owned_region(&mut self.padding_block);
    }

    fn squeeze_to_slice(&mut self, destination: &mut [u8]) {
        for target in destination {
            *target = self.next_byte();
        }
    }

    fn fill_staging(&mut self, count: usize) {
        for index in 0..count {
            let value = self.next_byte();
            if let Some(target) = self.squeeze_staging.get_mut(index) {
                *target = value;
            }
        }
    }

    fn next_byte(&mut self) -> u8 {
        if self.squeeze_position() == RATE {
            permutation::permute(self);
            self.set_squeeze_position(0);
        }
        let position = self.squeeze_position();
        let value = self.sponge_lanes.get(position).copied().unwrap_or(0);
        self.set_squeeze_position(position.saturating_add(1));
        value
    }
}

fn complete_output_bytes(length: usize, valid: u8) -> usize {
    if valid == 0 || valid == 8 {
        length
    } else {
        length.saturating_sub(1)
    }
}

fn low_mask(valid_bits: u8) -> u8 {
    u8::MAX
        .checked_shr(u32::from(8_u8.saturating_sub(valid_bits)))
        .unwrap_or_default()
}

fn read_counter(bytes: &[u8; 16]) -> u128 {
    let mut value = 0_u128;
    for (offset, byte) in bytes.iter().enumerate() {
        let shift = byte_shift(offset);
        value |= u128::from(*byte) << shift;
    }
    value
}

fn write_counter(bytes: &mut [u8; 16], value: u128) {
    for (offset, byte) in bytes.iter_mut().enumerate() {
        let shift = byte_shift(offset);
        *byte = u8::try_from((value >> shift) & u128::from(u8::MAX)).unwrap_or_default();
    }
}

fn byte_shift(offset: usize) -> u32 {
    u32::try_from(offset)
        .unwrap_or_default()
        .checked_mul(8)
        .unwrap_or_default()
}

#[cfg(kani)]
mod proofs {
    use super::{complete_output_bytes, low_mask};

    #[kani::proof]
    fn final_output_partition_never_exceeds_destination() {
        let length: usize = kani::any();
        let valid: u8 = kani::any();
        kani::assume(valid <= 8);
        assert!(complete_output_bytes(length, valid) <= length);
        if length != 0 && (1..8).contains(&valid) {
            assert_eq!(complete_output_bytes(length, valid), length - 1);
        }
    }

    #[kani::proof]
    fn hardened_tail_mask_contains_exact_valid_positions() {
        let valid: u8 = kani::any();
        kani::assume((1..=8).contains(&valid));
        let mask = low_mask(valid);
        for position in 0_u8..8 {
            assert_eq!(mask & (1_u8 << position) != 0, position < valid);
        }
    }
}
