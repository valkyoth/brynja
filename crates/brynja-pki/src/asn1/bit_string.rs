//! Canonical BIT STRING and OCTET STRING values.

use super::{Asn1Error, require_primitive};
use crate::DerElement;

/// One borrowed primitive DER BIT STRING.
///
/// This type intentionally omits diagnostic formatting.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BitString<'input> {
    bytes: &'input [u8],
    unused_bits: u8,
    bit_len: usize,
}

impl<'input> BitString<'input> {
    /// Validates the canonical unused-bit count and zero padding.
    pub fn decode(element: DerElement<'input>) -> Result<Self, Asn1Error> {
        require_primitive(element, 3)?;
        let Some((&unused_bits, bytes)) = element.contents().split_first() else {
            return Err(Asn1Error::InvalidBitString);
        };
        if unused_bits > 7 || (bytes.is_empty() && unused_bits != 0) {
            return Err(Asn1Error::InvalidBitString);
        }
        if unused_bits != 0 {
            let Some(last) = bytes.last().copied() else {
                return Err(Asn1Error::InvalidBitString);
            };
            let mask = (1_u8 << unused_bits).wrapping_sub(1);
            if last & mask != 0 {
                return Err(Asn1Error::InvalidBitString);
            }
        }
        let total = bytes.len().checked_mul(8).ok_or(Asn1Error::ValueOverflow)?;
        let bit_len = total
            .checked_sub(usize::from(unused_bits))
            .ok_or(Asn1Error::InvalidBitString)?;
        Ok(Self {
            bytes,
            unused_bits,
            bit_len,
        })
    }

    /// Borrows the data octets without the initial unused-bit count.
    #[must_use]
    pub const fn bytes(self) -> &'input [u8] {
        self.bytes
    }

    /// Returns the number of unused low bits in the final octet.
    #[must_use]
    pub const fn unused_bits(self) -> u8 {
        self.unused_bits
    }

    /// Returns the exact abstract bit length.
    #[must_use]
    pub const fn bit_len(self) -> usize {
        self.bit_len
    }
}

/// One borrowed primitive DER OCTET STRING.
///
/// This type intentionally omits diagnostic formatting.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct OctetString<'input> {
    bytes: &'input [u8],
}

impl<'input> OctetString<'input> {
    /// Validates the universal primitive OCTET STRING tag.
    pub fn decode(element: DerElement<'input>) -> Result<Self, Asn1Error> {
        require_primitive(element, 4)?;
        Ok(Self {
            bytes: element.contents(),
        })
    }

    /// Borrows the exact contents octets.
    #[must_use]
    pub const fn as_bytes(self) -> &'input [u8] {
        self.bytes
    }
}
