//! Canonical primitive character strings with closed admitted repertoires.

use super::{Asn1Error, require_primitive};
use crate::DerElement;

/// Admitted universal character-string type.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum CharacterStringKind {
    /// ASN.1 UTF8String.
    Utf8,
    /// ASN.1 NumericString.
    Numeric,
    /// ASN.1 PrintableString.
    Printable,
    /// ASN.1 IA5String.
    Ia5,
    /// ASN.1 VisibleString.
    Visible,
    /// ASN.1 UniversalString in four-octet ISO/IEC 10646 form.
    Universal,
    /// ASN.1 BMPString in two-octet ISO/IEC 10646 form.
    Bmp,
}

/// One borrowed canonical DER character string.
///
/// Escape-bearing ISO/IEC 2022 types remain rejected because their character
/// registry state is not admitted at this milestone. This type intentionally
/// omits diagnostic formatting.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CharacterString<'input> {
    kind: CharacterStringKind,
    bytes: &'input [u8],
}

impl<'input> CharacterString<'input> {
    /// Validates the primitive form and the selected type's complete contents.
    pub fn decode(element: DerElement<'input>) -> Result<Self, Asn1Error> {
        let number = element.tag().number();
        let kind = match number {
            12 => CharacterStringKind::Utf8,
            18 => CharacterStringKind::Numeric,
            19 => CharacterStringKind::Printable,
            22 => CharacterStringKind::Ia5,
            26 => CharacterStringKind::Visible,
            28 => CharacterStringKind::Universal,
            30 => CharacterStringKind::Bmp,
            _ => return Err(Asn1Error::UnsupportedType),
        };
        require_primitive(element, number)?;
        let bytes = element.contents();
        let valid = match kind {
            CharacterStringKind::Utf8 => core::str::from_utf8(bytes).is_ok(),
            CharacterStringKind::Numeric => bytes
                .iter()
                .all(|octet| octet.is_ascii_digit() || *octet == b' '),
            CharacterStringKind::Printable => bytes.iter().all(is_printable),
            CharacterStringKind::Ia5 => bytes.iter().all(u8::is_ascii),
            CharacterStringKind::Visible => bytes.iter().all(|octet| (0x20..=0x7e).contains(octet)),
            CharacterStringKind::Universal => valid_universal(bytes),
            CharacterStringKind::Bmp => valid_bmp(bytes),
        };
        if !valid {
            return Err(Asn1Error::InvalidCharacterString);
        }
        Ok(Self { kind, bytes })
    }

    /// Returns the declared string type.
    #[must_use]
    pub const fn kind(self) -> CharacterStringKind {
        self.kind
    }

    /// Borrows the exact canonical contents octets.
    #[must_use]
    pub const fn as_bytes(self) -> &'input [u8] {
        self.bytes
    }

    /// Borrows UTF-8 text for the UTF-8 and admitted single-octet types.
    #[must_use]
    pub fn as_str(self) -> Option<&'input str> {
        match self.kind {
            CharacterStringKind::Universal | CharacterStringKind::Bmp => None,
            _ => core::str::from_utf8(self.bytes).ok(),
        }
    }
}

fn is_printable(octet: &u8) -> bool {
    octet.is_ascii_alphanumeric()
        || matches!(
            *octet,
            b' ' | b'\'' | b'(' | b')' | b'+' | b',' | b'-' | b'.' | b'/' | b':' | b'=' | b'?'
        )
}

fn valid_bmp(bytes: &[u8]) -> bool {
    let mut chunks = bytes.chunks_exact(2);
    let valid = chunks.all(|chunk| {
        let Ok(array) = <[u8; 2]>::try_from(chunk) else {
            return false;
        };
        let scalar = u16::from_be_bytes(array);
        !(0xd800..=0xdfff).contains(&scalar)
    });
    valid && chunks.remainder().is_empty()
}

fn valid_universal(bytes: &[u8]) -> bool {
    let mut chunks = bytes.chunks_exact(4);
    let valid = chunks.all(|chunk| {
        let Ok(array) = <[u8; 4]>::try_from(chunk) else {
            return false;
        };
        char::from_u32(u32::from_be_bytes(array)).is_some()
    });
    valid && chunks.remainder().is_empty()
}
