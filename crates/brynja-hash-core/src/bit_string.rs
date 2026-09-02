/// A canonical borrowed bit string with most-significant-bit-first ordering.
///
/// A nonempty byte-aligned string uses `8` valid bits in its final byte. An
/// empty string uses `0`. For a partial final byte, the valid bits occupy the
/// high end of that byte and every unused low bit must be zero. This removes
/// the ambiguity between message bits and storage padding.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BitString<'input> {
    bytes: &'input [u8],
    bit_len: usize,
    valid_bits_in_last_byte: u8,
}

impl<'input> BitString<'input> {
    /// Validates one canonical borrowed bit string.
    ///
    /// `valid_bits_in_last_byte` must be `0` for an empty string and in
    /// `1..=8` for a nonempty string. A value of `8` means the final byte is
    /// complete.
    pub fn new(bytes: &'input [u8], valid_bits_in_last_byte: u8) -> Result<Self, BitStringError> {
        if bytes.is_empty() {
            return if valid_bits_in_last_byte == 0 {
                Ok(Self {
                    bytes,
                    bit_len: 0,
                    valid_bits_in_last_byte,
                })
            } else {
                Err(BitStringError::InvalidValidBitCount)
            };
        }
        if !(1..=8).contains(&valid_bits_in_last_byte) {
            return Err(BitStringError::InvalidValidBitCount);
        }
        let complete_bytes = bytes
            .len()
            .checked_sub(1)
            .and_then(|length| length.checked_mul(8))
            .ok_or(BitStringError::LengthOverflow)?;
        let bit_len = complete_bytes
            .checked_add(usize::from(valid_bits_in_last_byte))
            .ok_or(BitStringError::LengthOverflow)?;
        if valid_bits_in_last_byte < 8 {
            let unused_mask = u8::MAX >> valid_bits_in_last_byte;
            if bytes.last().copied().unwrap_or(0) & unused_mask != 0 {
                return Err(BitStringError::NonZeroUnusedBits);
            }
        }
        Ok(Self {
            bytes,
            bit_len,
            valid_bits_in_last_byte,
        })
    }

    /// Returns the backing bytes, including a possible canonical partial byte.
    #[must_use]
    pub const fn as_bytes(self) -> &'input [u8] {
        self.bytes
    }

    /// Returns the exact number of message bits.
    #[must_use]
    pub const fn bit_len(self) -> usize {
        self.bit_len
    }

    /// Returns the number of valid high bits in the final backing byte.
    #[must_use]
    pub const fn valid_bits_in_last_byte(self) -> u8 {
        self.valid_bits_in_last_byte
    }

    /// Returns whether the message ends at a byte boundary.
    #[must_use]
    pub const fn is_byte_aligned(self) -> bool {
        self.valid_bits_in_last_byte == 0 || self.valid_bits_in_last_byte == 8
    }

    /// Separates complete message bytes from the optional canonical tail.
    ///
    /// The tuple contains the partial byte followed by its valid high-bit
    /// count. It is absent for empty and byte-aligned strings.
    #[must_use]
    pub fn split(self) -> (&'input [u8], Option<(u8, u8)>) {
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

/// Closed canonical bit-string construction failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum BitStringError {
    /// Empty and nonempty inputs require different valid-bit count domains.
    InvalidValidBitCount,
    /// One or more unused low bits in the final byte were nonzero.
    NonZeroUnusedBits,
    /// The exact bit length could not be represented by this target.
    LengthOverflow,
}

#[cfg(test)]
mod tests {
    use super::{BitString, BitStringError};

    #[test]
    fn canonical_domains_are_exact() {
        let empty = BitString::new(&[], 0);
        assert!(empty.is_ok());
        if let Ok(empty) = empty {
            assert_eq!(empty.bit_len(), 0);
            assert!(empty.is_byte_aligned());
        }

        let aligned = BitString::new(&[0xa5, 0x5a], 8);
        assert!(aligned.is_ok());
        if let Ok(aligned) = aligned {
            assert_eq!(aligned.bit_len(), 16);
            assert_eq!(aligned.split(), (&[0xa5, 0x5a][..], None));
        }

        let partial = BitString::new(&[0xa5, 0xa0], 3);
        assert!(partial.is_ok());
        if let Ok(partial) = partial {
            assert_eq!(partial.bit_len(), 11);
            assert_eq!(partial.split(), (&[0xa5][..], Some((0xa0, 3))));
        }
    }

    #[test]
    fn ambiguous_representations_are_rejected() {
        assert!(matches!(
            BitString::new(&[], 1),
            Err(BitStringError::InvalidValidBitCount)
        ));
        assert!(matches!(
            BitString::new(&[0], 0),
            Err(BitStringError::InvalidValidBitCount)
        ));
        assert!(matches!(
            BitString::new(&[0], 9),
            Err(BitStringError::InvalidValidBitCount)
        ));
        for valid in 1..8 {
            assert!(matches!(
                BitString::new(&[1], valid),
                Err(BitStringError::NonZeroUnusedBits)
            ));
        }
    }
}
