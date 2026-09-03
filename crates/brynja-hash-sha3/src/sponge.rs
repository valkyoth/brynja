use crate::keccak::{byte, permute, xor_byte};

pub(super) const MAX_RATE_BYTES: usize = 168;
pub(super) const SHA3_SUFFIX: u8 = 0x06;
pub(super) const SHAKE_SUFFIX: u8 = 0x1f;
const SHA3_SUFFIX_BITS: u8 = 3;
const SHAKE_SUFFIX_BITS: u8 = 5;

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

    pub(super) fn check_additional_bits(&self, additional: u128) -> Result<(), ()> {
        checked_bit_length(self.message_bytes, additional).map(|_| ())
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
        self.apply_padding(None, SHA3_SUFFIX, SHA3_SUFFIX_BITS);

        let mut output = [0_u8; OUTPUT];
        for (position, target) in output.iter_mut().enumerate() {
            *target = byte(&self.state, position);
        }
        output
    }

    pub(super) fn finalize_xof(mut self) -> Squeezer<RATE> {
        self.apply_padding(None, SHAKE_SUFFIX, SHAKE_SUFFIX_BITS);
        Squeezer::new(self.state)
    }

    pub(super) fn finalize_domain_xof(
        mut self,
        partial: Option<(u8, u8)>,
        suffix: u8,
        suffix_bits: u8,
    ) -> Squeezer<RATE> {
        self.apply_padding(partial, suffix, suffix_bits);
        Squeezer::new(self.state)
    }

    pub(super) fn finalize_bits<const OUTPUT: usize>(
        mut self,
        partial: Option<(u8, u8)>,
    ) -> [u8; OUTPUT] {
        self.apply_padding(partial, SHA3_SUFFIX, SHA3_SUFFIX_BITS);
        let mut output = [0_u8; OUTPUT];
        for (position, target) in output.iter_mut().enumerate() {
            *target = byte(&self.state, position);
        }
        output
    }

    pub(super) fn finalize_bits_xof(mut self, partial: Option<(u8, u8)>) -> Squeezer<RATE> {
        self.apply_padding(partial, SHAKE_SUFFIX, SHAKE_SUFFIX_BITS);
        Squeezer::new(self.state)
    }

    fn apply_padding(&mut self, partial: Option<(u8, u8)>, suffix: u8, suffix_bits: u8) {
        let mut bit_position = self.buffer_len.saturating_mul(8);
        if let Some((byte, valid_bits)) = partial {
            if let Some(target) = self.buffer.get_mut(self.buffer_len) {
                *target = byte & low_mask(valid_bits);
            }
            bit_position = bit_position.saturating_add(usize::from(valid_bits));
        }
        for suffix_position in 0..suffix_bits {
            if bit_position == RATE.saturating_mul(8) {
                absorb(&mut self.state, &self.buffer, RATE);
                self.buffer.fill(0);
                bit_position = 0;
            }
            if suffix & (1_u8 << suffix_position) != 0 {
                let byte_position = bit_position / 8;
                let bit_in_byte = bit_position % 8;
                if let Some(target) = self.buffer.get_mut(byte_position) {
                    *target ^= 1_u8 << bit_in_byte;
                }
            }
            bit_position = bit_position.saturating_add(1);
        }
        if bit_position == RATE.saturating_mul(8) {
            absorb(&mut self.state, &self.buffer, RATE);
            self.buffer.fill(0);
        }
        if let Some(last) = self.buffer.get_mut(RATE.saturating_sub(1)) {
            *last ^= 0x80;
        }
        absorb(&mut self.state, &self.buffer, RATE);
    }
}

pub(super) struct Squeezer<const RATE: usize> {
    state: [u64; 25],
    position: usize,
    output_bytes: u128,
}

impl<const RATE: usize> Squeezer<RATE> {
    pub(super) const MAX_OUTPUT_BYTES: u128 = u128::MAX;

    const fn new(state: [u64; 25]) -> Self {
        Self {
            state,
            position: 0,
            output_bytes: 0,
        }
    }

    pub(super) const fn output_bytes(&self) -> u128 {
        self.output_bytes
    }

    pub(super) fn check_additional_bytes(&self, additional: u128) -> Result<(), ()> {
        checked_output_length(self.output_bytes, additional).map(|_| ())
    }

    pub(super) fn check_additional_bits(&self, additional: u128) -> Result<(), ()> {
        checked_bit_length(self.output_bytes, additional).map(|_| ())
    }

    pub(super) fn squeeze(&mut self, output: &mut [u8]) -> Result<(), ()> {
        let additional = u128::try_from(output.len()).map_err(|_| ())?;
        let new_length = checked_output_length(self.output_bytes, additional)?;

        for target in output.iter_mut() {
            if self.position == RATE {
                permute(&mut self.state);
                self.position = 0;
            }
            *target = byte(&self.state, self.position);
            self.position = self.position.saturating_add(1);
        }
        self.output_bytes = new_length;
        Ok(())
    }

    pub(super) fn squeeze_final_bits(
        mut self,
        mut output: crate::Fips202Output<'_>,
    ) -> Result<(), ()> {
        let additional = u128::try_from(output.bit_len()).map_err(|_| ())?;
        checked_bit_length(self.output_bytes, additional)?;
        let (complete, partial) = output.split_mut();
        self.squeeze(complete)?;
        if let Some((target, valid_bits)) = partial {
            *target = self.next_byte() & low_mask(valid_bits);
        }
        Ok(())
    }

    fn next_byte(&mut self) -> u8 {
        if self.position == RATE {
            permute(&mut self.state);
            self.position = 0;
        }
        let output = byte(&self.state, self.position);
        self.position = self.position.saturating_add(1);
        output
    }
}

fn absorb(state: &mut [u64; 25], block: &[u8], rate: usize) {
    for (position, value) in block.iter().take(rate).enumerate() {
        xor_byte(state, position, *value);
    }
    permute(state);
}

fn low_mask(valid_bits: u8) -> u8 {
    u8::MAX
        .checked_shr(u32::from(8_u8.saturating_sub(valid_bits)))
        .unwrap_or_default()
}

pub(crate) const fn checked_message_length(current: u128, additional: u128) -> Result<u128, ()> {
    match current.checked_add(additional) {
        Some(length) => Ok(length),
        None => Err(()),
    }
}

pub(crate) const fn checked_bit_length(
    current_bytes: u128,
    additional_bits: u128,
) -> Result<(u128, u8), ()> {
    let additional_bytes = additional_bits / 8;
    let remaining_bits = (additional_bits % 8) as u8;
    match current_bytes.checked_add(additional_bytes) {
        Some(bytes) => Ok((bytes, remaining_bits)),
        None => Err(()),
    }
}

pub(crate) const fn checked_output_length(current: u128, additional: u128) -> Result<u128, ()> {
    match current.checked_add(additional) {
        Some(length) => Ok(length),
        None => Err(()),
    }
}

#[cfg(kani)]
mod proofs {
    use super::{checked_bit_length, low_mask};

    #[kani::proof]
    fn checked_bit_length_preserves_quotient_and_remainder() {
        let bytes: u128 = kani::any();
        let bits: u128 = kani::any();
        let expected = bytes
            .checked_add(bits / 8)
            .map(|whole| (whole, (bits % 8) as u8))
            .ok_or(());
        assert_eq!(checked_bit_length(bytes, bits), expected);
    }

    #[kani::proof]
    fn low_mask_contains_exactly_the_valid_positions() {
        let valid: u8 = kani::any();
        kani::assume(valid >= 1 && valid <= 8);
        let mask = low_mask(valid);
        for position in 0_u8..8 {
            assert_eq!(mask & (1_u8 << position) != 0, position < valid);
        }
    }
}
