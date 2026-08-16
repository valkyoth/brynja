//! Security-first, first-party Rust `no_std` cryptography and protocol facade.
//!
//! This release exposes all six complete portable FIPS 180-4 SHA-2 algorithms through
//! distinct one-shot and streaming APIs: [`crypto::sha224`],
//! [`crypto::sha256`], [`crypto::sha384`], [`crypto::sha512`],
//! [`crypto::sha512_224`], and [`crypto::sha512_256`] plus their matching
//! state and digest types. It exposes checked
//! numeric/resource domains, transactional borrowed cursors, caller-owned
//! workspaces, secret-lifetime and owned-memory
//! foundations, fixed-width constant-time operations, provider capability
//! contracts with opaque exact-operation handles, and typed wall and monotonic
//! clocks. Pending certificate, external-signature, and accelerator operations
//! have an affine bounded lifecycle. An inert FIPS-aware architecture freezes
//! service, environment, SSP, self-test, and permanent-failure contracts
//! without implementing or claiming a validated module. Mandatory typed
//! security outcomes now bind exact decision domains to authoritative state,
//! including token-gated external-key destruction. Bounded observational
//! events duplicate those outcomes without gaining authority. Shared TLS and
//! DTLS record envelopes are now parsed and encoded independently of protocol
//! selection. A bounded borrowed DER reader exposes canonical framing and
//! values without schema-driven ASN.1 or X.509 semantics. This crate does not
//! provide a TLS connection API, provider effect, or any cryptographic
//! algorithm outside these six SHA-2 identities.

#![no_std]

/// Whether this facade provides its complete planned protocol implementation.
///
/// This remains `false`; the exposed completed core foundations have explicit
/// flags.
pub const IMPLEMENTED: bool = false;

pub use brynja_core as core;
pub use brynja_crypto as crypto;
pub use brynja_pki as pki;
pub use brynja_protocol as protocol;
pub use brynja_tls as tls;

#[cfg(feature = "dtls")]
pub use brynja_dtls as dtls;
#[cfg(feature = "platform")]
pub use brynja_platform as platform;
#[cfg(feature = "quic")]
pub use brynja_quic_tls as quic_tls;

#[cfg(test)]
mod tests {
    #[test]
    fn facade_claims_only_completed_foundation_domains() {
        assert!(!::core::hint::black_box(super::IMPLEMENTED));
        assert!(::core::hint::black_box(
            super::core::READ_CURSOR_IMPLEMENTED
        ));
        assert!(::core::hint::black_box(
            super::core::WRITE_CURSOR_IMPLEMENTED
        ));
        assert!(::core::hint::black_box(
            super::core::WORKSPACE_ARENAS_IMPLEMENTED
        ));
        assert!(::core::hint::black_box(
            super::core::SECRET_LIFETIME_CONTRACT_IMPLEMENTED
        ));
        assert!(::core::hint::black_box(
            super::core::OWNED_MEMORY_ZEROIZATION_IMPLEMENTED
        ));
        assert!(::core::hint::black_box(
            super::core::CONSTANT_TIME_FOUNDATION_IMPLEMENTED
        ));
        assert!(::core::hint::black_box(
            super::core::PROVIDER_CONTRACTS_IMPLEMENTED
        ));
        assert!(::core::hint::black_box(
            super::core::CPU_BACKEND_CONTRACT_IMPLEMENTED
        ));
        assert!(::core::hint::black_box(
            super::core::CLOCK_CONTRACT_IMPLEMENTED
        ));
        assert!(::core::hint::black_box(
            super::core::PENDING_OPERATION_LIFECYCLE_IMPLEMENTED
        ));
        assert!(::core::hint::black_box(
            super::core::FIPS_AWARE_PROVIDER_ARCHITECTURE_IMPLEMENTED
        ));
        assert!(::core::hint::black_box(
            super::core::SECURITY_OUTCOME_AUTHORITY_CONTRACT_IMPLEMENTED
        ));
        assert!(::core::hint::black_box(
            super::core::SECURITY_EVENT_SCHEMA_IMPLEMENTED
        ));
        assert!(::core::hint::black_box(
            super::protocol::TLS_DTLS_RECORD_FRAMING_IMPLEMENTED
        ));
        assert!(::core::hint::black_box(
            super::pki::BOUNDED_DER_READER_IMPLEMENTED
        ));
        assert!(::core::hint::black_box(super::crypto::SHA224_IMPLEMENTED));
        assert!(::core::hint::black_box(super::crypto::SHA256_IMPLEMENTED));
        assert!(::core::hint::black_box(super::crypto::SHA384_IMPLEMENTED));
        assert!(::core::hint::black_box(super::crypto::SHA512_IMPLEMENTED));
        assert!(::core::hint::black_box(
            super::crypto::SHA512_224_IMPLEMENTED
        ));
        assert!(::core::hint::black_box(
            super::crypto::SHA512_256_IMPLEMENTED
        ));
        assert_eq!(
            super::crypto::sha224(b"abc"),
            Ok(super::crypto::Sha224Digest::from_bytes([
                0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22, 0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2,
                0x55, 0xb3, 0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7, 0xe3, 0x6c, 0x9d, 0xa7,
            ]))
        );
        let mut output = [];
        let cursor = super::core::WriteCursor::new(&mut output);
        assert_eq!(cursor.finish().map(|finished| finished.len()), Ok(0));
    }
}
