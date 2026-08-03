//! Security-first, dependency-free `no_std` TLS facade.
//!
//! This release exposes checked numeric/resource domains and transactional
//! borrowed input consumption. It does not yet provide a TLS connection API.

#![no_std]

/// Whether this package provides its planned implementation.
///
/// The borrowed-read milestone intentionally reports `false`.
pub const IMPLEMENTED: bool = false;

pub use brynja_core as core;
pub use brynja_crypto as crypto;
pub use brynja_pki as pki;
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
    fn policy_release_does_not_claim_implementation() {
        assert!(!::core::hint::black_box(super::IMPLEMENTED));
        assert!(::core::hint::black_box(
            super::core::READ_CURSOR_IMPLEMENTED
        ));
        let cursor = super::core::ReadCursor::new(&[]);
        assert_eq!(cursor.finish(), Ok(()));
    }
}
