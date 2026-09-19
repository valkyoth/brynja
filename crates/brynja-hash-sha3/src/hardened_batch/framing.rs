//! Virtual SP 800-185 input. Only bounded metadata/encodings are materialized.
use super::{Error, Input};
use brynja_core::clear_owned_region;

pub(super) fn number(bytes: &[u8; 8]) -> Result<usize, Error> {
    usize::try_from(u64::from_le_bytes(*bytes)).map_err(|_| Error::Invariant)
}
pub(super) fn store(out: &mut [u8; 8], value: usize) -> Result<(), Error> {
    *out = u64::try_from(value)
        .map_err(|_| Error::MessageTooLong)?
        .to_le_bytes();
    Ok(())
}
pub(super) fn mask(bits: usize) -> u8 {
    match bits {
        0 => 0,
        1 => 1,
        2 => 3,
        3 => 7,
        4 => 15,
        5 => 31,
        6 => 63,
        7 => 127,
        _ => 255,
    }
}
pub(super) struct Frame {
    lengths: [[u8; 8]; 9],
    integers: [[u8; 17]; 3],
    cursor: [[u8; 8]; 4], // part, offset, remaining absorb blocks, total permutations
    suffix: [u8; 1],
}
impl Frame {
    #[cfg(test)]
    pub fn is_cleared(&self) -> bool {
        self.lengths
            .as_flattened()
            .iter()
            .chain(self.integers.as_flattened())
            .chain(self.cursor.as_flattened())
            .chain(&self.suffix)
            .all(|b| *b == 0)
    }
    pub const fn new() -> Self {
        Self {
            lengths: [[0; 8]; 9],
            integers: [[0; 17]; 3],
            cursor: [[0; 8]; 4],
            suffix: [0],
        }
    }
    pub fn wipe(&mut self) {
        let _ = clear_owned_region(self.lengths.as_flattened_mut());
        let _ = clear_owned_region(self.integers.as_flattened_mut());
        let _ = clear_owned_region(self.cursor.as_flattened_mut());
        let _ = clear_owned_region(&mut self.suffix);
    }
    fn len(&self, index: usize) -> Result<usize, Error> {
        number(self.lengths.get(index).ok_or(Error::Invariant)?)
    }
    fn set_len(&mut self, index: usize, value: usize) -> Result<(), Error> {
        store(self.lengths.get_mut(index).ok_or(Error::Invariant)?, value)
    }
    fn encode(&mut self, part: usize, slot: usize, value: usize) -> Result<(), Error> {
        // Rate/length are explicitly public metadata. No secret bytes enter
        // the ordinary public integer encoder; its result is public too.
        let encoded = crate::left_encode_u128(value as u128);
        let bytes = encoded.as_bytes();
        self.integers
            .get_mut(slot)
            .and_then(|out| out.get_mut(..bytes.len()))
            .ok_or(Error::Invariant)?
            .copy_from_slice(bytes);
        self.set_len(part, bytes.len().checked_mul(8).ok_or(Error::Invariant)?)
    }
    pub fn initialize(&mut self, input: &Input<'_>) -> Result<(), Error> {
        self.wipe();
        let rate = input.algorithm.rate();
        let rate_bits = rate.checked_mul(8).ok_or(Error::Invariant)?;
        let customized = input.algorithm.customized()
            && (input.name.bit_len() != 0 || input.customization.bit_len() != 0);
        let mut prefix = 0_usize;
        if customized {
            self.encode(0, 0, rate)?;
            self.encode(1, 1, input.name.bit_len())?;
            self.set_len(2, input.name.bit_len())?;
            self.encode(3, 2, input.customization.bit_len())?;
            self.set_len(4, input.customization.bit_len())?;
            for index in 0..5 {
                prefix = prefix
                    .checked_add(self.len(index)?)
                    .ok_or(Error::MessageTooLong)?;
            }
            let zeros = rate_bits
                .checked_sub(prefix.checked_rem(rate_bits).ok_or(Error::Invariant)?)
                .ok_or(Error::Invariant)?
                .checked_rem(rate_bits)
                .ok_or(Error::Invariant)?;
            self.set_len(5, zeros)?;
            prefix = prefix.checked_add(zeros).ok_or(Error::MessageTooLong)?;
        }
        self.set_len(6, input.message.bit_len())?;
        let (suffix, bits) = if customized {
            (4, 3)
        } else if input.algorithm.fixed_output_bits().is_some() {
            (6, 3)
        } else {
            (31, 5)
        };
        self.suffix = [suffix];
        self.set_len(7, bits)?;
        let before = prefix
            .checked_add(input.message.bit_len())
            .and_then(|n| n.checked_add(bits))
            .ok_or(Error::MessageTooLong)?;
        let padding = rate_bits
            .checked_sub(before.checked_rem(rate_bits).ok_or(Error::Invariant)?)
            .ok_or(Error::Invariant)?;
        self.set_len(8, padding)?;
        let blocks = before
            .checked_add(padding)
            .ok_or(Error::MessageTooLong)?
            .checked_div(rate_bits)
            .ok_or(Error::Invariant)?;
        let squeezes = input
            .output_bytes()
            .saturating_sub(1)
            .checked_div(rate)
            .ok_or(Error::Invariant)?;
        let total = blocks.checked_add(squeezes).ok_or(Error::MessageTooLong)?;
        let [_, _, remaining, permutations] = &mut self.cursor;
        store(remaining, blocks)?;
        store(permutations, total)?;
        Ok(())
    }
    pub fn remaining(&self) -> Result<usize, Error> {
        number(self.cursor.get(2).ok_or(Error::Invariant)?)
    }
    pub fn permutations(&self) -> Result<usize, Error> {
        number(self.cursor.get(3).ok_or(Error::Invariant)?)
    }
    fn xor_part(
        &self,
        input: &Input<'_>,
        part: usize,
        offset: usize,
        count: usize,
        destination: &mut u8,
        left: usize,
    ) -> Result<(), Error> {
        let end = offset.checked_add(count).ok_or(Error::Invariant)?;
        let available = 8_usize.checked_sub(count).ok_or(Error::Invariant)?;
        if count == 0 || left > available || end > self.len(part)? {
            return Err(Error::Invariant);
        }
        let bytes = match part {
            0 | 1 | 3 => self
                .integers
                .get(match part {
                    0 => 0,
                    1 => 1,
                    _ => 2,
                })
                .ok_or(Error::Invariant)?
                .as_slice(),
            2 => input.name.as_bytes(),
            4 => input.customization.as_bytes(),
            5 => return Ok(()),
            6 => input.message.as_bytes(),
            7 => {
                return xor_bits(destination, &self.suffix[0], offset, count, left);
            }
            8 => {
                // Padding is public metadata, never a secret-derived byte.
                let padding = if end == self.len(part)? {
                    1 << count.checked_sub(1).ok_or(Error::Invariant)?
                } else {
                    0
                };
                return xor_bits(destination, &padding, 0, count, left);
            }
            _ => return Err(Error::Invariant),
        };
        // At most two disjoint fragments; no secret byte is returned or
        // assembled in a Rust local. XOR distributes over these disjoint bits.
        let first = count.min(8_usize.checked_sub(offset % 8).ok_or(Error::Invariant)?);
        xor_bits(
            destination,
            bytes.get(offset / 8).ok_or(Error::Invariant)?,
            offset % 8,
            first,
            left,
        )?;
        if first < count {
            xor_bits(
                destination,
                bytes
                    .get((offset / 8).checked_add(1).ok_or(Error::Invariant)?)
                    .ok_or(Error::Invariant)?,
                0,
                count.checked_sub(first).ok_or(Error::Invariant)?,
                left.checked_add(first).ok_or(Error::Invariant)?,
            )?;
        }
        Ok(())
    }
    fn absorb_byte(&mut self, input: &Input<'_>, destination: &mut u8) -> Result<(), Error> {
        let mut filled = 0_usize;
        while filled < 8 {
            let [part, position, ..] = &self.cursor;
            let index = number(part)?;
            let offset = number(position)?;
            let remaining = self
                .len(index)?
                .checked_sub(offset)
                .ok_or(Error::Invariant)?;
            if remaining == 0 {
                let [part, position, ..] = &mut self.cursor;
                store(part, index.checked_add(1).ok_or(Error::Invariant)?)?;
                store(position, 0)?;
                continue;
            }
            let count = remaining.min(8_usize.checked_sub(filled).ok_or(Error::Invariant)?);
            self.xor_part(input, index, offset, count, destination, filled)?;
            store(
                self.cursor.get_mut(1).ok_or(Error::Invariant)?,
                offset.checked_add(count).ok_or(Error::Invariant)?,
            )?;
            filled = filled.checked_add(count).ok_or(Error::Invariant)?;
        }
        Ok(())
    }
    pub fn absorb(&mut self, input: &Input<'_>, state: &mut [u8; 200]) -> Result<(), Error> {
        let remaining = self.remaining()?.checked_sub(1).ok_or(Error::Invariant)?;
        for out in state
            .get_mut(..input.algorithm.rate())
            .ok_or(Error::Invariant)?
        {
            self.absorb_byte(input, out)?;
        }
        store(self.cursor.get_mut(2).ok_or(Error::Invariant)?, remaining)
    }
}
fn xor_bits(
    destination: &mut u8,
    source: &u8,
    right: usize,
    count: usize,
    left: usize,
) -> Result<(), Error> {
    brynja_core::xor_secret_byte_bits(
        destination,
        source,
        u8::try_from(right).map_err(|_| Error::Invariant)?,
        u8::try_from(count).map_err(|_| Error::Invariant)?,
        u8::try_from(left).map_err(|_| Error::Invariant)?,
    )
    .map_err(|_| Error::Invariant)
}
impl Drop for Frame {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn borrowed_fragments_cross_byte_boundaries_without_changing_other_bits() -> Result<(), Error> {
        let bytes = [0x96, 0x69];
        let bits = crate::Fips202BitString::new(&bytes, 8).map_err(|_| Error::Invariant)?;
        let input = Input::new(super::super::Algorithm::Shake128, bits, 1)?;
        let mut frame = Frame::new();
        frame.initialize(&input)?;
        for offset in 0..16 {
            for count in 1..=8.min(16 - offset) {
                for left in 0..=8 - count {
                    let mut out = 0xa5;
                    frame.xor_part(&input, 6, offset, count, &mut out, left)?;
                    let value = (u16::from_le_bytes(bytes) >> offset) & ((1_u16 << count) - 1);
                    assert_eq!(
                        out,
                        0xa5 ^ u8::try_from(value << left).map_err(|_| Error::Invariant)?
                    );
                }
            }
        }
        for (offset, count, left) in [
            (0, 0, 0),
            (0, 9, 0),
            (15, 2, 0),
            (0, 1, 8),
            (usize::MAX, 1, 0),
        ] {
            let mut out = 0xa5;
            assert_eq!(
                frame.xor_part(&input, 6, offset, count, &mut out, left),
                Err(Error::Invariant)
            );
            assert_eq!(out, 0xa5);
        }
        Ok(())
    }
}
