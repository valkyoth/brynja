//! Shared allocation-free wire framing for Brynja protocol engines.
//!
//! The crate parses and writes record envelopes only. It does not negotiate a
//! protocol version, decrypt records, maintain replay state, or implement a
//! handshake. Callers must supply an already selected typed protocol profile.

#![no_std]

pub mod tls;

pub use tls::{
    ContentType, ContentTypeClass, ContentTypeCode, Dtls12Ciphertext, Dtls13Ciphertext,
    Dtls13CiphertextConfig, Dtls13CiphertextHeader, Dtls13Sequence, DtlsPlaintext,
    HEARTBEAT_EXTENSION_TYPE, LegacyRecordVersion, RecordError, TlsCiphertext, TlsPlaintext,
    WirePolicy, encode_dtls13_ciphertext,
};

/// Whether the bounded TLS and DTLS framing boundary is implemented.
pub const TLS_DTLS_RECORD_FRAMING_IMPLEMENTED: bool = true;

#[cfg(test)]
mod tests {
    #[test]
    fn package_claims_only_record_framing() {
        assert!(::core::hint::black_box(
            super::TLS_DTLS_RECORD_FRAMING_IMPLEMENTED
        ));
    }
}
