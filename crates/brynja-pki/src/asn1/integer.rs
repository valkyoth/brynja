//! Minimal two's-complement INTEGER values.

use super::{Asn1Error, IntegerValueError, require_primitive};
use crate::DerElement;

/// One borrowed canonical DER INTEGER.
///
/// The exact signed bytes remain caller-owned. This type intentionally omits
/// diagnostic formatting.
///
/// ```compile_fail
/// # let bytes = [0x02, 0x01, 0x01];
/// # let limits: brynja_pki::DerLimits = todo!();
/// # let mut reader = brynja_pki::Reader::<2>::new(&bytes, limits).unwrap();
/// # let brynja_pki::DerEvent::Primitive(element) = reader.next_event().unwrap().unwrap() else { unreachable!() };
/// let integer = brynja_pki::CanonicalInteger::decode(element).unwrap();
/// println!("{integer:?}");
/// ```
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CanonicalInteger<'input> {
    bytes: &'input [u8],
}

impl<'input> CanonicalInteger<'input> {
    /// Validates the universal primitive tag and minimal two's-complement form.
    pub fn decode(element: DerElement<'input>) -> Result<Self, Asn1Error> {
        require_primitive(element, 2)?;
        let bytes = element.contents();
        let Some((&first, rest)) = bytes.split_first() else {
            return Err(Asn1Error::InvalidInteger);
        };
        if let Some(&second) = rest.first()
            && ((first == 0 && second & 0x80 == 0) || (first == 0xff && second & 0x80 != 0))
        {
            return Err(Asn1Error::InvalidInteger);
        }
        Ok(Self { bytes })
    }

    /// Borrows the exact minimal two's-complement contents.
    #[must_use]
    pub const fn as_bytes(self) -> &'input [u8] {
        self.bytes
    }

    /// Reports whether the value is negative.
    #[must_use]
    pub fn is_negative(self) -> bool {
        self.bytes.first().is_some_and(|first| first & 0x80 != 0)
    }

    /// Converts to `i64`, rejecting wider canonical values.
    pub fn try_i64(self) -> Result<i64, IntegerValueError> {
        if self.bytes.len() > core::mem::size_of::<i64>() {
            return Err(IntegerValueError::Overflow);
        }
        let fill = if self.is_negative() { 0xff } else { 0 };
        let mut output = [fill; core::mem::size_of::<i64>()];
        copy_to_end(self.bytes, &mut output)?;
        Ok(i64::from_be_bytes(output))
    }

    /// Converts a non-negative value to `u64`, rejecting negative or wider values.
    pub fn try_u64(self) -> Result<u64, IntegerValueError> {
        if self.is_negative() {
            return Err(IntegerValueError::Negative);
        }
        let extended_width = core::mem::size_of::<u64>()
            .checked_add(1)
            .ok_or(IntegerValueError::Overflow)?;
        let bytes = if self.bytes.len() == extended_width {
            let Some((&zero, rest)) = self.bytes.split_first() else {
                return Err(IntegerValueError::Overflow);
            };
            if zero != 0 || rest.len() != core::mem::size_of::<u64>() {
                return Err(IntegerValueError::Overflow);
            }
            rest
        } else {
            self.bytes
        };
        if bytes.len() > core::mem::size_of::<u64>() {
            return Err(IntegerValueError::Overflow);
        }
        let mut output = [0_u8; core::mem::size_of::<u64>()];
        copy_to_end(bytes, &mut output)?;
        Ok(u64::from_be_bytes(output))
    }
}

fn copy_to_end<const N: usize>(
    input: &[u8],
    output: &mut [u8; N],
) -> Result<(), IntegerValueError> {
    let start = N
        .checked_sub(input.len())
        .ok_or(IntegerValueError::Overflow)?;
    let destination = output.get_mut(start..).ok_or(IntegerValueError::Overflow)?;
    destination.copy_from_slice(input);
    Ok(())
}
