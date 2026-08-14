//! Canonical ASN.1 values carried by bounded DER elements.

mod bit_string;
mod constructed;
mod error;
mod integer;
mod object_identifier;
mod string;
mod time;
mod value;

pub use bit_string::{BitString, OctetString};
pub use constructed::{CanonicalSequence, CanonicalSet, CanonicalSetOf};
pub use error::{Asn1Error, IntegerValueError};
pub use integer::CanonicalInteger;
pub use object_identifier::{ObjectIdentifier, ObjectIdentifierArcs};
pub use string::{CharacterString, CharacterStringKind};
pub use time::{GeneralizedTime, UtcTime};
pub use value::CanonicalValue;

use crate::{DerElement, TagClass};

fn require_primitive(element: DerElement<'_>, number: u64) -> Result<(), Asn1Error> {
    require_universal(element, number, false)
}

fn require_constructed(element: DerElement<'_>, number: u64) -> Result<(), Asn1Error> {
    require_universal(element, number, true)
}

fn require_universal(
    element: DerElement<'_>,
    number: u64,
    constructed: bool,
) -> Result<(), Asn1Error> {
    let tag = element.tag();
    if tag.class() != TagClass::Universal {
        return Err(Asn1Error::NonUniversalTag);
    }
    if tag.number() != number {
        return Err(Asn1Error::UnexpectedTag);
    }
    if tag.is_constructed() != constructed {
        return Err(Asn1Error::InvalidEncodingForm);
    }
    Ok(())
}
