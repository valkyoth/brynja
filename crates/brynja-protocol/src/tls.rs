//! Version-neutral TLS and DTLS record envelopes.

mod content_type;
mod dtls;
mod dtls12_ciphertext;
mod error;
mod record;

pub use content_type::{
    ContentType, ContentTypeClass, ContentTypeCode, HEARTBEAT_EXTENSION_TYPE, WirePolicy,
};
pub use dtls::{
    Dtls13Ciphertext, Dtls13CiphertextConfig, Dtls13CiphertextHeader, Dtls13Sequence,
    DtlsPlaintext, encode_dtls13_ciphertext,
};
pub use dtls12_ciphertext::Dtls12Ciphertext;
pub use error::RecordError;
pub use record::{LegacyRecordVersion, TlsCiphertext, TlsPlaintext};

/// Maximum unprotected TLS or DTLS record content length.
pub const MAX_PLAINTEXT_LENGTH: usize = 1 << 14;
/// Maximum TLS 1.2 or DTLS 1.2 protected record fragment length.
pub const MAX_TLS12_CIPHERTEXT_LENGTH: usize = MAX_PLAINTEXT_LENGTH + 2_048;
/// Maximum TLS 1.3 or DTLS 1.3 protected record fragment length.
pub const MAX_TLS13_CIPHERTEXT_LENGTH: usize = MAX_PLAINTEXT_LENGTH + 256;
