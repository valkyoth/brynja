/// A canonical FIPS 202 bit string.
///
/// FIPS 202 maps bits least-significant-bit first within each byte. A partial
/// final byte therefore stores its valid bits in the low end, and all unused
/// high bits must be zero.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Fips202BitString<'input> {
    bytes: &'input [u8],
    bit_len: usize,
    valid_bits_in_last_byte: u8,
}

impl<'input> Fips202BitString<'input> {
    /// Validates a borrowed FIPS 202 bit-string representation.
    pub fn new(bytes: &'input [u8], valid_bits_in_last_byte: u8) -> Result<Self, Fips202BitsError> {
        validate_shape(bytes.len(), valid_bits_in_last_byte)?;
        let bit_len = exact_bit_len(bytes.len(), valid_bits_in_last_byte)?;
        if valid_bits_in_last_byte < 8 && !bytes.is_empty() {
            let unused_mask = u8::MAX << valid_bits_in_last_byte;
            if bytes.last().copied().unwrap_or(0) & unused_mask != 0 {
                return Err(Fips202BitsError::NonZeroUnusedBits);
            }
        }
        Ok(Self {
            bytes,
            bit_len,
            valid_bits_in_last_byte,
        })
    }

    /// Returns the canonical backing bytes.
    #[must_use]
    pub const fn as_bytes(self) -> &'input [u8] {
        self.bytes
    }

    /// Returns the exact message length in bits.
    #[must_use]
    pub const fn bit_len(self) -> usize {
        self.bit_len
    }

    /// Returns the number of valid low bits in the final byte.
    #[must_use]
    pub const fn valid_bits_in_last_byte(self) -> u8 {
        self.valid_bits_in_last_byte
    }

    /// Returns whether this string ends on a byte boundary.
    #[must_use]
    pub const fn is_byte_aligned(self) -> bool {
        self.valid_bits_in_last_byte == 0 || self.valid_bits_in_last_byte == 8
    }

    pub(crate) fn split(self) -> (&'input [u8], Option<(u8, u8)>) {
        if self.is_byte_aligned() {
            return (self.bytes, None);
        }
        let split = self.bytes.len().saturating_sub(1);
        let (complete, tail) = self.bytes.split_at(split);
        (
            complete,
            tail.first()
                .copied()
                .map(|byte| (byte, self.valid_bits_in_last_byte)),
        )
    }
}

/// A caller-owned destination for a canonical FIPS 202 output bit string.
pub struct Fips202Output<'output> {
    bytes: &'output mut [u8],
    bit_len: usize,
    valid_bits_in_last_byte: u8,
}

impl<'output> Fips202Output<'output> {
    /// Validates the destination shape. Existing bytes are ignored.
    pub fn new(
        bytes: &'output mut [u8],
        valid_bits_in_last_byte: u8,
    ) -> Result<Self, Fips202BitsError> {
        validate_shape(bytes.len(), valid_bits_in_last_byte)?;
        let bit_len = exact_bit_len(bytes.len(), valid_bits_in_last_byte)?;
        Ok(Self {
            bytes,
            bit_len,
            valid_bits_in_last_byte,
        })
    }

    /// Returns the exact requested output length in bits.
    #[must_use]
    pub const fn bit_len(&self) -> usize {
        self.bit_len
    }

    pub(crate) fn split_mut(&mut self) -> (&mut [u8], Option<(&mut u8, u8)>) {
        if self.valid_bits_in_last_byte == 0 || self.valid_bits_in_last_byte == 8 {
            return (self.bytes, None);
        }
        let split = self.bytes.len().saturating_sub(1);
        let (complete, tail) = self.bytes.split_at_mut(split);
        (
            complete,
            tail.first_mut()
                .map(|byte| (byte, self.valid_bits_in_last_byte)),
        )
    }

    pub(crate) fn into_parts(self) -> (&'output mut [u8], u8) {
        (self.bytes, self.valid_bits_in_last_byte)
    }
}

/// A closed canonical FIPS 202 bit representation failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Fips202BitsError {
    /// Empty and nonempty values require different final-bit count domains.
    InvalidValidBitCount,
    /// An input partial byte contained nonzero unused high bits.
    NonZeroUnusedBits,
    /// The exact bit length cannot be represented on this target.
    LengthOverflow,
}

fn validate_shape(length: usize, valid: u8) -> Result<(), Fips202BitsError> {
    if length == 0 {
        return if valid == 0 {
            Ok(())
        } else {
            Err(Fips202BitsError::InvalidValidBitCount)
        };
    }
    if (1..=8).contains(&valid) {
        Ok(())
    } else {
        Err(Fips202BitsError::InvalidValidBitCount)
    }
}

fn exact_bit_len(length: usize, valid: u8) -> Result<usize, Fips202BitsError> {
    length
        .checked_sub(1)
        .and_then(|complete| complete.checked_mul(8))
        .and_then(|bits| bits.checked_add(usize::from(valid)))
        .or(if length == 0 { Some(0) } else { None })
        .ok_or(Fips202BitsError::LengthOverflow)
}

#[cfg(kani)]
mod proofs {
    use super::{exact_bit_len, validate_shape};

    #[kani::proof]
    fn canonical_shape_has_exact_length() {
        let length: usize = kani::any();
        let valid: u8 = kani::any();
        kani::assume(length <= 4_096);
        if validate_shape(length, valid).is_ok() {
            let expected = if length == 0 {
                0
            } else {
                (length - 1) * 8 + usize::from(valid)
            };
            assert_eq!(exact_bit_len(length, valid), Ok(expected));
        }
    }
}
