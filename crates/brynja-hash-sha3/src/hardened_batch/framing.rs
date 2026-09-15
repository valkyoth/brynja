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
    fn read(
        &self,
        input: &Input<'_>,
        part: usize,
        offset: usize,
        count: usize,
    ) -> Result<u8, Error> {
        let end = offset.checked_add(count).ok_or(Error::Invariant)?;
        if count > 8 || end > self.len(part)? {
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
            5 => return Ok(0),
            6 => input.message.as_bytes(),
            7 => {
                return Ok(self.suffix[0]
                    .checked_shr(u32::try_from(offset).map_err(|_| Error::Invariant)?)
                    .ok_or(Error::Invariant)?
                    & mask(count));
            }
            8 => {
                return Ok(if end == self.len(part)? && count != 0 {
                    1 << count.checked_sub(1).ok_or(Error::Invariant)?
                } else {
                    0
                });
            }
            _ => return Err(Error::Invariant),
        };
        let first = u16::from(*bytes.get(offset / 8).ok_or(Error::Invariant)?);
        let second = if (offset % 8).checked_add(count).ok_or(Error::Invariant)? > 8 {
            u16::from(
                *bytes
                    .get((offset / 8).checked_add(1).ok_or(Error::Invariant)?)
                    .ok_or(Error::Invariant)?,
            )
        } else {
            0
        };
        u8::try_from(((first | (second << 8)) >> (offset % 8)) & u16::from(mask(count)))
            .map_err(|_| Error::Invariant)
    }
    fn next_byte(&mut self, input: &Input<'_>) -> Result<u8, Error> {
        let mut byte = 0;
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
            byte |= self.read(input, index, offset, count)? << filled;
            store(
                self.cursor.get_mut(1).ok_or(Error::Invariant)?,
                offset.checked_add(count).ok_or(Error::Invariant)?,
            )?;
            filled = filled.checked_add(count).ok_or(Error::Invariant)?;
        }
        Ok(byte)
    }
    pub fn absorb(&mut self, input: &Input<'_>, state: &mut [u8; 200]) -> Result<(), Error> {
        let remaining = self.remaining()?.checked_sub(1).ok_or(Error::Invariant)?;
        for out in state
            .get_mut(..input.algorithm.rate())
            .ok_or(Error::Invariant)?
        {
            *out ^= self.next_byte(input)?;
        }
        store(self.cursor.get_mut(2).ok_or(Error::Invariant)?, remaining)
    }
}
impl Drop for Frame {
    fn drop(&mut self) {
        self.wipe();
    }
}
