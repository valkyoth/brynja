//! Virtual, bounded SP 800-185/FIPS 202 input; never allocate an encoded prefix.
use super::{Error, Input};
use crate::{Fips202BitString, left_encode_u128};

enum Part<'a> {
    Bits(Fips202BitString<'a>),
    Integer([u8; 17], usize),
    Zeros(usize),
    Suffix(u8, usize),
    Padding(usize),
}
impl Part<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Bits(b) => b.bit_len(),
            Self::Integer(_, n) => n << 3,
            Self::Zeros(n) | Self::Padding(n) | Self::Suffix(_, n) => *n,
        }
    }
    // At most eight low-order bits; handles bit-packed N/S boundaries too.
    fn read(&self, offset: usize, count: usize) -> Result<u8, Error> {
        let end = offset.checked_add(count).ok_or(Error::Invariant)?;
        if count > 8 || end > self.len() {
            return Err(Error::Invariant);
        }
        let bytes = match self {
            Self::Zeros(_) => return Ok(0),
            Self::Padding(n) => {
                return Ok(if end == *n && count != 0 {
                    1 << count.checked_sub(1).ok_or(Error::Invariant)?
                } else {
                    0
                });
            }
            Self::Suffix(value, _) => return Ok((*value >> offset) & mask(count)),
            Self::Bits(bits) => bits.as_bytes(),
            Self::Integer(bytes, n) => bytes.get(..*n).ok_or(Error::Invariant)?,
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
}
pub(super) fn mask(count: usize) -> u8 {
    match count {
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
fn integer(value: usize) -> Result<Part<'static>, Error> {
    let encoded = left_encode_u128(value as u128);
    let n = encoded.as_bytes().len();
    let mut bytes = [0; 17];
    bytes
        .get_mut(..n)
        .ok_or(Error::Invariant)?
        .copy_from_slice(encoded.as_bytes());
    Ok(Part::Integer(bytes, n))
}
fn padding(bits: usize, rate: usize) -> Result<usize, Error> {
    rate.checked_sub(bits.checked_rem(rate).ok_or(Error::Invariant)?)
        .ok_or(Error::Invariant)
}

pub(super) struct Cursor<'a> {
    parts: [Part<'a>; 9],
    index: usize,
    offset: usize,
    pub remaining_blocks: usize,
    pub permutations: usize,
}
impl<'a> Cursor<'a> {
    pub fn new(input: Input<'a>) -> Result<Self, Error> {
        let rate = input.algorithm.rate();
        let rate_bits = rate.checked_mul(8).ok_or(Error::Invariant)?;
        let mut parts = core::array::from_fn(|_| Part::Zeros(0));
        let customized = input.algorithm.customized()
            && (input.name.bit_len() != 0 || input.customization.bit_len() != 0);
        let [
            width,
            name_len,
            name,
            custom_len,
            custom,
            prefix_pad,
            message,
            suffix,
            pad,
        ] = &mut parts;
        let mut prefix_bits = 0_usize;
        if customized {
            *width = integer(rate)?;
            *name_len = integer(input.name.bit_len())?;
            *name = Part::Bits(input.name);
            *custom_len = integer(input.customization.bit_len())?;
            *custom = Part::Bits(input.customization);
            for part in [&*width, &*name_len, &*name, &*custom_len, &*custom] {
                prefix_bits = prefix_bits
                    .checked_add(part.len())
                    .ok_or(Error::MessageTooLong)?;
            }
            let zeros = padding(prefix_bits, rate_bits)?
                .checked_rem(rate_bits)
                .ok_or(Error::Invariant)?;
            *prefix_pad = Part::Zeros(zeros);
            prefix_bits = prefix_bits
                .checked_add(zeros)
                .ok_or(Error::MessageTooLong)?;
        }
        *message = Part::Bits(input.message);
        let (value, length) = if customized {
            (4, 3)
        } else if input.algorithm.fixed_output_bits().is_some() {
            (6, 3)
        } else {
            (31, 5)
        };
        *suffix = Part::Suffix(value, length);
        let before_pad = prefix_bits
            .checked_add(input.message.bit_len())
            .and_then(|n| n.checked_add(length))
            .ok_or(Error::MessageTooLong)?;
        // At least one bit remains for the terminal 1, including exact collision.
        let padding = padding(before_pad, rate_bits)?;
        *pad = Part::Padding(padding);
        let total = before_pad
            .checked_add(padding)
            .ok_or(Error::MessageTooLong)?;
        let remaining_blocks = total.checked_div(rate_bits).ok_or(Error::Invariant)?;
        let extra_squeezes = input
            .output_bytes()
            .saturating_sub(1)
            .checked_div(rate)
            .ok_or(Error::Invariant)?;
        let permutations = remaining_blocks
            .checked_add(extra_squeezes)
            .ok_or(Error::MessageTooLong)?;
        Ok(Self {
            parts,
            index: 0,
            offset: 0,
            remaining_blocks,
            permutations,
        })
    }
    fn next_byte(&mut self) -> Result<u8, Error> {
        let mut byte = 0;
        let mut filled = 0_usize;
        while filled < 8 {
            let part = self.parts.get(self.index).ok_or(Error::Invariant)?;
            let remaining = part
                .len()
                .checked_sub(self.offset)
                .ok_or(Error::Invariant)?;
            if remaining == 0 {
                self.index = self.index.checked_add(1).ok_or(Error::Invariant)?;
                self.offset = 0;
                continue;
            }
            let count = remaining.min(8_usize.checked_sub(filled).ok_or(Error::Invariant)?);
            byte |= part.read(self.offset, count)? << filled;
            self.offset = self.offset.checked_add(count).ok_or(Error::Invariant)?;
            filled = filled.checked_add(count).ok_or(Error::Invariant)?;
        }
        Ok(byte)
    }
    pub fn absorb_block(&mut self, state: &mut [u64; 25], rate: usize) -> Result<(), Error> {
        if !matches!(rate, 72 | 104 | 136 | 144 | 168) {
            return Err(Error::Invariant);
        }
        let remaining = self
            .remaining_blocks
            .checked_sub(1)
            .ok_or(Error::Invariant)?;
        for position in 0..rate {
            let byte = self.next_byte()?;
            *state.get_mut(position / 8).ok_or(Error::Invariant)? ^=
                u64::from(byte) << ((position % 8) << 3);
        }
        self.remaining_blocks = remaining;
        Ok(())
    }
}
