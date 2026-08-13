//! Closed TLS ContentType registry policy.

use brynja_core::ProtocolVersion;

use super::RecordError;

/// The RFC 6520 Heartbeat extension code, retained only for rejection.
pub const HEARTBEAT_EXTENSION_TYPE: u16 = 15;

/// An assigned TLS ContentType value relevant to modern record framing.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ContentType {
    /// `change_cipher_spec` (20).
    ChangeCipherSpec,
    /// `alert` (21).
    Alert,
    /// `handshake` (22).
    Handshake,
    /// `application_data` (23).
    ApplicationData,
    /// Excluded RFC 6520 `heartbeat` (24).
    Heartbeat,
    /// DTLS 1.2 Connection ID content (25), reserved for a later owner.
    Tls12Cid,
    /// DTLS 1.3 acknowledgement content (26).
    Ack,
}

/// The exact current classification of one wire byte.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ContentTypeClass {
    /// A currently assigned code.
    Assigned(ContentType),
    /// An unassigned code retained without coercion.
    Unassigned,
}

/// One exact byte from the TLS ContentType registry.
///
/// Construction preserves unknown values. Admission remains a separate,
/// profile-specific operation.
///
/// ```compile_fail
/// let _ = brynja_protocol::ContentTypeCode(23);
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ContentTypeCode(u8);

/// Closed record wire policy for one already selected protocol version.
///
/// The policy cannot be inferred from record-layer version bytes, so framing
/// cannot negotiate, downgrade, or fall back between protocol versions.
///
/// ```compile_fail
/// let _ = brynja_protocol::WirePolicy {
///     version: brynja_core::ProtocolVersion::Tls13,
/// };
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct WirePolicy {
    version: ProtocolVersion,
}

impl ContentType {
    /// Returns the assigned registry byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::ChangeCipherSpec => 20,
            Self::Alert => 21,
            Self::Handshake => 22,
            Self::ApplicationData => 23,
            Self::Heartbeat => 24,
            Self::Tls12Cid => 25,
            Self::Ack => 26,
        }
    }
}

impl ContentTypeCode {
    /// Preserves and classifies one registry byte.
    #[must_use]
    pub const fn classify(code: u8) -> Self {
        Self(code)
    }

    /// Returns the exact original wire byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        self.0
    }

    /// Returns the exact current registry class without fallback.
    #[must_use]
    pub const fn class(self) -> ContentTypeClass {
        let assigned = match self.0 {
            20 => Some(ContentType::ChangeCipherSpec),
            21 => Some(ContentType::Alert),
            22 => Some(ContentType::Handshake),
            23 => Some(ContentType::ApplicationData),
            24 => Some(ContentType::Heartbeat),
            25 => Some(ContentType::Tls12Cid),
            26 => Some(ContentType::Ack),
            _ => None,
        };
        match assigned {
            Some(content_type) => ContentTypeClass::Assigned(content_type),
            None => ContentTypeClass::Unassigned,
        }
    }
}

impl WirePolicy {
    /// Binds framing to an externally selected typed protocol version.
    #[must_use]
    pub const fn for_version(version: ProtocolVersion) -> Self {
        Self { version }
    }

    /// Returns the externally selected version.
    #[must_use]
    pub const fn version(self) -> ProtocolVersion {
        self.version
    }

    /// Rejects Heartbeat negotiation before extension state can be created.
    ///
    /// Other extension codes are not admitted by this method; they merely
    /// remain outside this narrow exclusion check for their later owners.
    pub const fn reject_heartbeat_negotiation(
        self,
        extension_type: u16,
    ) -> Result<(), RecordError> {
        let _ = self;
        if extension_type == HEARTBEAT_EXTENSION_TYPE {
            Err(RecordError::HeartbeatRejected)
        } else {
            Ok(())
        }
    }

    /// Admits an already decrypted TLS 1.3 or DTLS 1.3 inner content type.
    ///
    /// Heartbeat is rejected for both families. Earlier profiles have no
    /// inner-content envelope and fail with [`RecordError::ProfileMismatch`].
    pub fn admit_inner_content_type(
        self,
        code: ContentTypeCode,
    ) -> Result<ContentType, RecordError> {
        let content_type = assigned(code)?;
        if matches!(content_type, ContentType::Heartbeat) {
            return Err(RecordError::HeartbeatRejected);
        }
        let admitted = match self.version {
            ProtocolVersion::Tls13 => matches!(
                content_type,
                ContentType::Alert | ContentType::Handshake | ContentType::ApplicationData
            ),
            ProtocolVersion::Dtls13 => matches!(
                content_type,
                ContentType::Alert
                    | ContentType::Handshake
                    | ContentType::ApplicationData
                    | ContentType::Ack
            ),
            _ => return Err(RecordError::ProfileMismatch),
        };
        if admitted {
            Ok(content_type)
        } else {
            Err(RecordError::UnsupportedContentType)
        }
    }

    pub(crate) fn admit_plaintext(self, code: ContentTypeCode) -> Result<ContentType, RecordError> {
        let content_type = assigned(code)?;
        if matches!(content_type, ContentType::Heartbeat) {
            return Err(RecordError::HeartbeatRejected);
        }
        let admitted = match self.version {
            ProtocolVersion::Tls12 | ProtocolVersion::Tls13 => matches!(
                content_type,
                ContentType::ChangeCipherSpec
                    | ContentType::Alert
                    | ContentType::Handshake
                    | ContentType::ApplicationData
            ),
            ProtocolVersion::Dtls12 => matches!(
                content_type,
                ContentType::ChangeCipherSpec
                    | ContentType::Alert
                    | ContentType::Handshake
                    | ContentType::ApplicationData
            ),
            ProtocolVersion::Dtls13 => matches!(
                content_type,
                ContentType::Alert | ContentType::Handshake | ContentType::Ack
            ),
            _ => false,
        };
        if admitted {
            Ok(content_type)
        } else {
            Err(RecordError::UnsupportedContentType)
        }
    }

    pub(crate) fn admit_ciphertext(
        self,
        code: ContentTypeCode,
    ) -> Result<ContentType, RecordError> {
        if matches!(
            code.class(),
            ContentTypeClass::Assigned(ContentType::Heartbeat)
        ) {
            return Err(RecordError::HeartbeatRejected);
        }
        match self.version {
            ProtocolVersion::Tls13 => {
                if code.code() == ContentType::ApplicationData.code() {
                    Ok(ContentType::ApplicationData)
                } else {
                    Err(RecordError::InvalidCiphertextType)
                }
            }
            ProtocolVersion::Tls12 | ProtocolVersion::Dtls12 => self.admit_plaintext(code),
            ProtocolVersion::Dtls13 => Err(RecordError::ProfileMismatch),
            _ => Err(RecordError::ProfileMismatch),
        }
    }
}

fn assigned(code: ContentTypeCode) -> Result<ContentType, RecordError> {
    match code.class() {
        ContentTypeClass::Assigned(content_type) => Ok(content_type),
        ContentTypeClass::Unassigned => Err(RecordError::UnsupportedContentType),
    }
}
