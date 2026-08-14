//! First-party bounded DER and canonical ASN.1 foundations for Brynja.
//!
//! This package implements allocation-free DER traversal and a closed set of
//! canonical ASN.1 primitive and container decoders. X.509, certificate-chain
//! processing, revocation, and cryptographic verification remain unimplemented.

#![no_std]

mod asn1;
mod der;

pub use asn1::{
    Asn1Error, BitString, CanonicalInteger, CanonicalSequence, CanonicalSet, CanonicalSetOf,
    CanonicalValue, CharacterString, CharacterStringKind, GeneralizedTime, IntegerValueError,
    ObjectIdentifier, ObjectIdentifierArcs, OctetString, UtcTime,
};
pub use der::{
    DerElement, DerError, DerEvent, DerLimit, DerLimitBuildError, DerLimits, DerLimitsBuilder,
    Reader, Tag, TagClass,
};

/// Whether bounded DER identifier/length/value framing is implemented.
pub const BOUNDED_DER_READER_IMPLEMENTED: bool = true;

/// Whether the v0.21 canonical ASN.1 value boundary is implemented.
pub const CANONICAL_ASN1_PRIMITIVES_IMPLEMENTED: bool = true;

/// Whether the complete planned PKI implementation exists.
pub const IMPLEMENTED: bool = false;

#[cfg(test)]
mod tests {
    #[test]
    fn package_claims_only_completed_der_and_asn1_foundations() {
        assert!(::core::hint::black_box(
            super::BOUNDED_DER_READER_IMPLEMENTED
        ));
        assert!(::core::hint::black_box(
            super::CANONICAL_ASN1_PRIMITIVES_IMPLEMENTED
        ));
        assert!(!::core::hint::black_box(super::IMPLEMENTED));
    }
}
