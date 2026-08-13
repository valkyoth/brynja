//! First-party bounded DER framing for Brynja.
//!
//! This package currently implements only allocation-free DER identifier,
//! length, value, and constructed-nesting traversal. Type-specific ASN.1,
//! X.509, certificate-chain processing, revocation, and cryptographic verification remain
//! unimplemented.

#![no_std]

mod der;

pub use der::{
    DerElement, DerError, DerEvent, DerLimit, DerLimitBuildError, DerLimits, DerLimitsBuilder,
    Reader, Tag, TagClass,
};

/// Whether bounded DER identifier/length/value framing is implemented.
pub const BOUNDED_DER_READER_IMPLEMENTED: bool = true;

/// Whether the complete planned PKI implementation exists.
pub const IMPLEMENTED: bool = false;

#[cfg(test)]
mod tests {
    #[test]
    fn package_claims_only_bounded_der_framing() {
        assert!(::core::hint::black_box(
            super::BOUNDED_DER_READER_IMPLEMENTED
        ));
        assert!(!::core::hint::black_box(super::IMPLEMENTED));
    }
}
