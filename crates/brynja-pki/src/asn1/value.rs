//! Closed dispatch for admitted canonical ASN.1 values.

use super::{
    Asn1Error, BitString, CanonicalInteger, CanonicalSequence, CanonicalSet, CanonicalSetOf,
    CharacterString, GeneralizedTime, ObjectIdentifier, OctetString, UtcTime,
};
use crate::{DerElement, TagClass};

/// One validated canonical ASN.1 value from the admitted v0.21 type set.
///
/// Container variants can only be created from their separately validated
/// types. This enum intentionally omits diagnostic formatting.
///
/// ```compile_fail
/// let value: brynja_pki::CanonicalValue<'static> = todo!();
/// println!("{value:?}");
/// ```
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum CanonicalValue<'input> {
    /// A canonical BOOLEAN.
    Boolean(bool),
    /// A minimal signed INTEGER.
    Integer(CanonicalInteger<'input>),
    /// A primitive BIT STRING with canonical unused bits.
    BitString(BitString<'input>),
    /// A primitive OCTET STRING.
    OctetString(OctetString<'input>),
    /// A minimal bounded OBJECT IDENTIFIER.
    ObjectIdentifier(ObjectIdentifier<'input>),
    /// An admitted canonical character string.
    CharacterString(CharacterString<'input>),
    /// A canonical UTCTime.
    UtcTime(UtcTime<'input>),
    /// A canonical GeneralizedTime.
    GeneralizedTime(GeneralizedTime<'input>),
    /// A constructed SEQUENCE boundary.
    Sequence(CanonicalSequence<'input>),
    /// A tag-ordered SET boundary.
    Set(CanonicalSet<'input>),
    /// An encoding-ordered SET OF boundary.
    SetOf(CanonicalSetOf<'input>),
}

impl<'input> CanonicalValue<'input> {
    /// Decodes one admitted universal primitive without schema-dependent casts.
    pub fn decode_primitive(element: DerElement<'input>) -> Result<Self, Asn1Error> {
        let tag = element.tag();
        if tag.class() != TagClass::Universal {
            return Err(Asn1Error::NonUniversalTag);
        }
        match tag.number() {
            1 => decode_boolean(element).map(Self::Boolean),
            2 => CanonicalInteger::decode(element).map(Self::Integer),
            3 => BitString::decode(element).map(Self::BitString),
            4 => OctetString::decode(element).map(Self::OctetString),
            6 => ObjectIdentifier::decode(element).map(Self::ObjectIdentifier),
            12 | 18 | 19 | 22 | 26 | 28 | 30 => {
                CharacterString::decode(element).map(Self::CharacterString)
            }
            23 => UtcTime::decode(element).map(Self::UtcTime),
            24 => GeneralizedTime::decode(element).map(Self::GeneralizedTime),
            _ => Err(Asn1Error::UnsupportedType),
        }
    }

    /// Wraps an already validated SEQUENCE.
    #[must_use]
    pub const fn from_sequence(value: CanonicalSequence<'input>) -> Self {
        Self::Sequence(value)
    }

    /// Wraps an already validated SET.
    #[must_use]
    pub const fn from_set(value: CanonicalSet<'input>) -> Self {
        Self::Set(value)
    }

    /// Wraps an already validated SET OF.
    #[must_use]
    pub const fn from_set_of(value: CanonicalSetOf<'input>) -> Self {
        Self::SetOf(value)
    }
}

fn decode_boolean(element: DerElement<'_>) -> Result<bool, Asn1Error> {
    super::require_primitive(element, 1)?;
    match element.contents() {
        [0] => Ok(false),
        [0xff] => Ok(true),
        _ => Err(Asn1Error::InvalidBoolean),
    }
}
