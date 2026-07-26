//! Record-independent TLS 1.3 handshake engine for Brynja.
//!
//! This package is a compile-time boundary established by Brynja 0.1.0.
//! Protocol or cryptographic functionality is not implemented yet.
//! Stream TLS and QUIC may share this state machine, but records, packets,
//! retransmission, and transport behavior remain outside it.

#![no_std]

/// Whether this package provides its planned implementation.
///
/// The foundation release intentionally reports `false`.
pub const IMPLEMENTED: bool = false;

#[cfg(test)]
mod tests {
    #[test]
    fn foundation_does_not_claim_implementation() {
        assert!(!::core::hint::black_box(super::IMPLEMENTED));
    }
}
