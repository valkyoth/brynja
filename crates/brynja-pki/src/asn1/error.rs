//! Closed ASN.1 semantic failures.

/// A payload-free reason canonical ASN.1 value decoding failed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Asn1Error {
    /// ASN.1 semantics require a universal tag at this boundary.
    NonUniversalTag,
    /// The universal tag does not identify the requested value type.
    UnexpectedTag,
    /// DER requires the opposite primitive or constructed encoding form.
    InvalidEncodingForm,
    /// The universal primitive is outside the admitted v0.21 type set.
    UnsupportedType,
    /// A BOOLEAN is not the exact canonical `00` or `FF` encoding.
    InvalidBoolean,
    /// An INTEGER has empty or non-minimal two's-complement contents.
    InvalidInteger,
    /// A BIT STRING has an invalid unused-bit count or nonzero unused bit.
    InvalidBitString,
    /// An OBJECT IDENTIFIER is empty, truncated, non-minimal, or too large.
    InvalidObjectIdentifier,
    /// A character string is malformed for its declared universal type.
    InvalidCharacterString,
    /// A time is lexically, calendrically, or canonically invalid.
    InvalidTime,
    /// SET components are not in strictly ascending tag order.
    InvalidSetOrder,
    /// SET OF values are not in ascending padded-octet order.
    InvalidSetOfOrder,
    /// A checked size or scalar conversion cannot be represented.
    ValueOverflow,
    /// Nested DER framing failed while validating a constructed value.
    InvalidNestedDer,
}

/// A payload-free failure converting a canonical INTEGER to a machine value.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum IntegerValueError {
    /// A negative INTEGER cannot become an unsigned value.
    Negative,
    /// The canonical integer is wider than the requested machine value.
    Overflow,
}
