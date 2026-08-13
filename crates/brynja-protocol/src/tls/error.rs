//! Closed record-framing failures.

/// A closed, payload-free TLS or DTLS record-framing failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum RecordError {
    /// The selected parser does not support that protocol family.
    ProfileMismatch,
    /// The complete fixed or declared record was not available.
    Truncated,
    /// A checked length computation overflowed.
    LengthOverflow,
    /// A record exceeded its profile's fixed maximum.
    RecordOverflow,
    /// A record required a non-empty fragment.
    EmptyFragment,
    /// The content type is known but unavailable in this profile.
    UnsupportedContentType,
    /// RFC 6520 Heartbeat is deliberately excluded.
    HeartbeatRejected,
    /// TLS 1.3 application data was presented in an unprotected wire record.
    UnprotectedApplicationData,
    /// A protected TLS 1.3 record did not use outer type 23.
    InvalidCiphertextType,
    /// A protected TLS 1.3 record did not use legacy version 0x0303.
    InvalidCiphertextVersion,
    /// Generated TLS 1.3 plaintext did not use an allowed compatibility value.
    InvalidPlaintextVersion,
    /// A DTLS 1.3 plaintext record used a nonzero epoch.
    InvalidPlaintextEpoch,
    /// A DTLS 1.3 unified header had invalid fixed bits or layout.
    InvalidUnifiedHeader,
    /// DTLS 1.3 CID presence differed from the selected connection context.
    ConnectionIdMismatch,
    /// A caller-provided connection identifier length exceeded one byte.
    ConnectionIdTooLong,
    /// The caller output buffer was too small; no byte was changed.
    InsufficientOutput,
}
