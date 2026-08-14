//! Canonical SEQUENCE, SET, and SET OF containers.

use core::cmp::Ordering;

use super::{Asn1Error, require_constructed};
use crate::{DerElement, DerEvent, DerLimits, Reader, Tag, TagClass};

/// One borrowed constructed DER SEQUENCE.
///
/// Schema-specific component order and DEFAULT omission remain the caller's
/// later decoding responsibility. This type intentionally omits formatting.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CanonicalSequence<'input> {
    element: DerElement<'input>,
}

impl<'input> CanonicalSequence<'input> {
    /// Validates the universal constructed SEQUENCE tag and all nested framing.
    pub fn decode<const STACK: usize>(
        element: DerElement<'input>,
        limits: DerLimits,
    ) -> Result<Self, Asn1Error> {
        require_constructed(element, 16)?;
        validate_nested::<STACK>(element.contents(), limits)?;
        Ok(Self { element })
    }

    /// Borrows the concatenated child encodings.
    #[must_use]
    pub const fn contents(self) -> &'input [u8] {
        self.element.contents()
    }

    /// Borrows the complete SEQUENCE encoding.
    #[must_use]
    pub const fn encoded(self) -> &'input [u8] {
        self.element.encoded()
    }
}

/// One borrowed DER SET whose direct components have canonical tag order.
///
/// This decoder applies SET component ordering. Homogeneous `SET OF` values
/// must use [`CanonicalSetOf`] instead. This type omits formatting.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CanonicalSet<'input> {
    element: DerElement<'input>,
}

impl<'input> CanonicalSet<'input> {
    /// Validates framing and strictly ascending direct-component tag order.
    pub fn decode<const STACK: usize>(
        element: DerElement<'input>,
        limits: DerLimits,
    ) -> Result<Self, Asn1Error> {
        require_constructed(element, 17)?;
        let mut reader = Reader::<STACK>::new(element.contents(), limits)
            .map_err(|_| Asn1Error::InvalidNestedDer)?;
        let mut previous = None;
        while let Some(event) = reader
            .next_event()
            .map_err(|_| Asn1Error::InvalidNestedDer)?
        {
            if let Some(child) = direct_child(event) {
                let key = tag_key(child.tag());
                if previous.is_some_and(|prior| prior >= key) {
                    return Err(Asn1Error::InvalidSetOrder);
                }
                previous = Some(key);
            }
        }
        Ok(Self { element })
    }

    /// Borrows the concatenated ordered child encodings.
    #[must_use]
    pub const fn contents(self) -> &'input [u8] {
        self.element.contents()
    }

    /// Borrows the complete SET encoding.
    #[must_use]
    pub const fn encoded(self) -> &'input [u8] {
        self.element.encoded()
    }
}

/// One borrowed DER SET OF whose direct encodings are canonically ordered.
///
/// Comparisons follow X.690's trailing-zero padding rule. This type omits
/// formatting.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CanonicalSetOf<'input> {
    element: DerElement<'input>,
}

impl<'input> CanonicalSetOf<'input> {
    /// Validates framing and ascending direct-child padded-octet order.
    pub fn decode<const STACK: usize>(
        element: DerElement<'input>,
        limits: DerLimits,
    ) -> Result<Self, Asn1Error> {
        require_constructed(element, 17)?;
        let mut reader = Reader::<STACK>::new(element.contents(), limits)
            .map_err(|_| Asn1Error::InvalidNestedDer)?;
        let mut previous: Option<&[u8]> = None;
        while let Some(event) = reader
            .next_event()
            .map_err(|_| Asn1Error::InvalidNestedDer)?
        {
            if let Some(child) = direct_child(event) {
                if previous.is_some_and(|prior| {
                    padded_compare(prior, child.encoded()) == Ordering::Greater
                }) {
                    return Err(Asn1Error::InvalidSetOfOrder);
                }
                previous = Some(child.encoded());
            }
        }
        Ok(Self { element })
    }

    /// Borrows the concatenated ordered child encodings.
    #[must_use]
    pub const fn contents(self) -> &'input [u8] {
        self.element.contents()
    }

    /// Borrows the complete SET OF encoding.
    #[must_use]
    pub const fn encoded(self) -> &'input [u8] {
        self.element.encoded()
    }
}

fn direct_child(event: DerEvent<'_>) -> Option<DerElement<'_>> {
    match event {
        DerEvent::Primitive(element) | DerEvent::ConstructedStart(element)
            if element.depth() == 0 =>
        {
            Some(element)
        }
        _ => None,
    }
}

fn validate_nested<const STACK: usize>(
    contents: &[u8],
    limits: DerLimits,
) -> Result<(), Asn1Error> {
    let mut reader =
        Reader::<STACK>::new(contents, limits).map_err(|_| Asn1Error::InvalidNestedDer)?;
    while reader
        .next_event()
        .map_err(|_| Asn1Error::InvalidNestedDer)?
        .is_some()
    {}
    Ok(())
}

const fn tag_key(tag: Tag) -> (u8, u64) {
    let class = match tag.class() {
        TagClass::Universal => 0,
        TagClass::Application => 1,
        TagClass::ContextSpecific => 2,
        TagClass::Private => 3,
    };
    (class, tag.number())
}

fn padded_compare(left: &[u8], right: &[u8]) -> Ordering {
    let length = if left.len() > right.len() {
        left.len()
    } else {
        right.len()
    };
    for index in 0..length {
        let left_octet = left.get(index).copied().unwrap_or(0);
        let right_octet = right.get(index).copied().unwrap_or(0);
        match left_octet.cmp(&right_octet) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    Ordering::Equal
}
