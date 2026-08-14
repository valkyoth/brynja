//! Minimal base-128 OBJECT IDENTIFIER values.

use super::{Asn1Error, require_primitive};
use crate::DerElement;

/// One borrowed canonical DER OBJECT IDENTIFIER.
///
/// Arc values are bounded to `u64`; wider hostile subidentifiers fail closed.
/// This type intentionally omits diagnostic formatting.
///
/// ```compile_fail
/// let _ = brynja_pki::ObjectIdentifier { contents: &[] };
/// ```
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ObjectIdentifier<'input> {
    contents: &'input [u8],
}

impl<'input> ObjectIdentifier<'input> {
    /// Validates every minimal, terminated base-128 subidentifier once.
    pub fn decode(element: DerElement<'input>) -> Result<Self, Asn1Error> {
        require_primitive(element, 6)?;
        let contents = element.contents();
        if contents.is_empty() {
            return Err(Asn1Error::InvalidObjectIdentifier);
        }
        let mut position = 0;
        while position < contents.len() {
            let (_value, next) = decode_subidentifier(contents, position)?;
            position = next;
        }
        Ok(Self { contents })
    }

    /// Borrows the exact canonical contents octets.
    #[must_use]
    pub const fn as_bytes(self) -> &'input [u8] {
        self.contents
    }

    /// Iterates decoded arcs without allocation.
    #[must_use]
    pub const fn arcs(self) -> ObjectIdentifierArcs<'input> {
        ObjectIdentifierArcs {
            contents: self.contents,
            position: 0,
            second: None,
            first: true,
            failed: false,
        }
    }
}

/// Allocation-free iterator over validated OBJECT IDENTIFIER arcs.
///
/// The iterator intentionally omits diagnostic formatting.
pub struct ObjectIdentifierArcs<'input> {
    contents: &'input [u8],
    position: usize,
    second: Option<u64>,
    first: bool,
    failed: bool,
}

impl Iterator for ObjectIdentifierArcs<'_> {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        if let Some(second) = self.second.take() {
            return Some(second);
        }
        if self.position >= self.contents.len() {
            return None;
        }
        let (value, next) = match decode_subidentifier(self.contents, self.position) {
            Ok(decoded) => decoded,
            Err(_) => {
                self.failed = true;
                return None;
            }
        };
        self.position = next;
        if self.first {
            self.first = false;
            if value < 40 {
                self.second = Some(value);
                return Some(0);
            }
            if value < 80 {
                self.second = value.checked_sub(40);
                return Some(1);
            }
            self.second = value.checked_sub(80);
            return Some(2);
        }
        Some(value)
    }
}

fn decode_subidentifier(contents: &[u8], start: usize) -> Result<(u64, usize), Asn1Error> {
    let first = contents
        .get(start)
        .copied()
        .ok_or(Asn1Error::InvalidObjectIdentifier)?;
    if first == 0x80 {
        return Err(Asn1Error::InvalidObjectIdentifier);
    }
    let mut position = start;
    let mut value = 0_u64;
    loop {
        let octet = contents
            .get(position)
            .copied()
            .ok_or(Asn1Error::InvalidObjectIdentifier)?;
        value = value
            .checked_mul(128)
            .and_then(|current| current.checked_add(u64::from(octet & 0x7f)))
            .ok_or(Asn1Error::InvalidObjectIdentifier)?;
        position = position.checked_add(1).ok_or(Asn1Error::ValueOverflow)?;
        if octet & 0x80 == 0 {
            return Ok((value, position));
        }
    }
}
