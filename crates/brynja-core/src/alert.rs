//! Typed TLS and DTLS alert registry domains.

use crate::ProtocolVersion;

/// An assigned, non-reserved TLS alert description.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum AlertDescription {
    /// Orderly closure notification (0).
    CloseNotify,
    /// An unexpected protocol message (10).
    UnexpectedMessage,
    /// Authentication failed for a protected record (20).
    BadRecordMac,
    /// A record exceeded its permitted bound (22).
    RecordOverflow,
    /// No acceptable handshake parameters were found (40).
    HandshakeFailure,
    /// A certificate was malformed or invalid (42).
    BadCertificate,
    /// The certificate type was unsupported (43).
    UnsupportedCertificate,
    /// A certificate was revoked (44).
    CertificateRevoked,
    /// A certificate was expired (45).
    CertificateExpired,
    /// An unspecified certificate failure occurred (46).
    CertificateUnknown,
    /// A field violated protocol constraints (47).
    IllegalParameter,
    /// The certificate authority was unknown (48).
    UnknownCa,
    /// Access was denied (49).
    AccessDenied,
    /// A message could not be decoded (50).
    DecodeError,
    /// A cryptographic handshake operation failed (51).
    DecryptError,
    /// Too many DTLS connection identifiers were requested (52).
    TooManyCidsRequested,
    /// The protocol version was unsupported (70).
    ProtocolVersion,
    /// Negotiated security would be insufficient (71).
    InsufficientSecurity,
    /// An internal invariant or operation failed (80).
    InternalError,
    /// A downgrade fallback was inappropriate (86).
    InappropriateFallback,
    /// The initiating party canceled the handshake (90).
    UserCanceled,
    /// A required extension was absent (109).
    MissingExtension,
    /// An extension was unsupported (110).
    UnsupportedExtension,
    /// A server name was not recognized (112).
    UnrecognizedName,
    /// A certificate-status response was invalid (113).
    BadCertificateStatusResponse,
    /// A pre-shared-key identity was unknown (115).
    UnknownPskIdentity,
    /// A certificate was required (116).
    CertificateRequired,
    /// A general protocol error occurred (117).
    GeneralError,
    /// No application protocol could be negotiated (120).
    NoApplicationProtocol,
    /// Encrypted ClientHello retry was required (121).
    EchRequired,
}

/// Classification of every byte in the TLS AlertDescription registry.
///
/// Reserved and unassigned codes remain distinguishable and cannot be
/// mistaken for assigned alerts.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AlertCode {
    /// A currently assigned description.
    Assigned(AlertDescription),
    /// An explicitly reserved registry code.
    Reserved(u8),
    /// A currently unassigned registry code.
    Unassigned(u8),
}

/// The party that selected or received an alert.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AlertOrigin {
    /// Brynja selected the alert locally.
    Local,
    /// The peer supplied the alert.
    Peer,
}

/// The semantic class of an assigned alert.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AlertClass {
    /// Orderly close notification.
    Closure,
    /// Explicit handshake cancellation.
    Cancellation,
    /// A protocol failure.
    Error,
}

/// Alert severity selected by the hardened local policy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AlertSeverity {
    /// Non-error closure or cancellation.
    Warning,
    /// A failure that terminates the connection.
    Fatal,
}

/// A protocol-version-aware assigned alert.
///
/// This type intentionally has no `Debug` or `Display` implementation so it
/// cannot become an accidental log envelope for future failure context.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct Alert {
    version: ProtocolVersion,
    origin: AlertOrigin,
    description: AlertDescription,
}

impl AlertDescription {
    /// Returns the IANA numeric value.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::CloseNotify => 0,
            Self::UnexpectedMessage => 10,
            Self::BadRecordMac => 20,
            Self::RecordOverflow => 22,
            Self::HandshakeFailure => 40,
            Self::BadCertificate => 42,
            Self::UnsupportedCertificate => 43,
            Self::CertificateRevoked => 44,
            Self::CertificateExpired => 45,
            Self::CertificateUnknown => 46,
            Self::IllegalParameter => 47,
            Self::UnknownCa => 48,
            Self::AccessDenied => 49,
            Self::DecodeError => 50,
            Self::DecryptError => 51,
            Self::TooManyCidsRequested => 52,
            Self::ProtocolVersion => 70,
            Self::InsufficientSecurity => 71,
            Self::InternalError => 80,
            Self::InappropriateFallback => 86,
            Self::UserCanceled => 90,
            Self::MissingExtension => 109,
            Self::UnsupportedExtension => 110,
            Self::UnrecognizedName => 112,
            Self::BadCertificateStatusResponse => 113,
            Self::UnknownPskIdentity => 115,
            Self::CertificateRequired => 116,
            Self::GeneralError => 117,
            Self::NoApplicationProtocol => 120,
            Self::EchRequired => 121,
        }
    }

    /// Returns the alert's semantic outcome class.
    #[must_use]
    pub const fn class(self) -> AlertClass {
        match self {
            Self::CloseNotify => AlertClass::Closure,
            Self::UserCanceled => AlertClass::Cancellation,
            _ => AlertClass::Error,
        }
    }

    /// Returns the hardened local severity without caller override.
    #[must_use]
    pub const fn severity(self) -> AlertSeverity {
        match self.class() {
            AlertClass::Closure | AlertClass::Cancellation => AlertSeverity::Warning,
            AlertClass::Error => AlertSeverity::Fatal,
        }
    }

    /// Reports whether this assigned alert is admitted for a protocol version.
    #[must_use]
    pub const fn is_admitted_for(self, version: ProtocolVersion) -> bool {
        match self {
            Self::TooManyCidsRequested => matches!(version, ProtocolVersion::Dtls13),
            Self::MissingExtension
            | Self::CertificateRequired
            | Self::GeneralError
            | Self::EchRequired => version.is_13(),
            Self::InappropriateFallback => !version.is_13(),
            _ => true,
        }
    }
}

impl AlertCode {
    /// Classifies every possible registry byte without ambiguous coercion.
    #[must_use]
    pub const fn classify(code: u8) -> Self {
        match code {
            0 => Self::Assigned(AlertDescription::CloseNotify),
            10 => Self::Assigned(AlertDescription::UnexpectedMessage),
            20 => Self::Assigned(AlertDescription::BadRecordMac),
            22 => Self::Assigned(AlertDescription::RecordOverflow),
            40 => Self::Assigned(AlertDescription::HandshakeFailure),
            42 => Self::Assigned(AlertDescription::BadCertificate),
            43 => Self::Assigned(AlertDescription::UnsupportedCertificate),
            44 => Self::Assigned(AlertDescription::CertificateRevoked),
            45 => Self::Assigned(AlertDescription::CertificateExpired),
            46 => Self::Assigned(AlertDescription::CertificateUnknown),
            47 => Self::Assigned(AlertDescription::IllegalParameter),
            48 => Self::Assigned(AlertDescription::UnknownCa),
            49 => Self::Assigned(AlertDescription::AccessDenied),
            50 => Self::Assigned(AlertDescription::DecodeError),
            51 => Self::Assigned(AlertDescription::DecryptError),
            52 => Self::Assigned(AlertDescription::TooManyCidsRequested),
            70 => Self::Assigned(AlertDescription::ProtocolVersion),
            71 => Self::Assigned(AlertDescription::InsufficientSecurity),
            80 => Self::Assigned(AlertDescription::InternalError),
            86 => Self::Assigned(AlertDescription::InappropriateFallback),
            90 => Self::Assigned(AlertDescription::UserCanceled),
            109 => Self::Assigned(AlertDescription::MissingExtension),
            110 => Self::Assigned(AlertDescription::UnsupportedExtension),
            112 => Self::Assigned(AlertDescription::UnrecognizedName),
            113 => Self::Assigned(AlertDescription::BadCertificateStatusResponse),
            115 => Self::Assigned(AlertDescription::UnknownPskIdentity),
            116 => Self::Assigned(AlertDescription::CertificateRequired),
            117 => Self::Assigned(AlertDescription::GeneralError),
            120 => Self::Assigned(AlertDescription::NoApplicationProtocol),
            121 => Self::Assigned(AlertDescription::EchRequired),
            21 | 30 | 41 | 60 | 100 | 111 | 114 => Self::Reserved(code),
            _ => Self::Unassigned(code),
        }
    }
}

impl Alert {
    /// Constructs an admitted assigned alert.
    #[must_use]
    pub const fn new(
        version: ProtocolVersion,
        origin: AlertOrigin,
        description: AlertDescription,
    ) -> Option<Self> {
        if description.is_admitted_for(version) {
            Some(Self {
                version,
                origin,
                description,
            })
        } else {
            None
        }
    }

    /// Returns the concrete protocol version.
    #[must_use]
    pub const fn version(self) -> ProtocolVersion {
        self.version
    }

    /// Returns the alert origin.
    #[must_use]
    pub const fn origin(self) -> AlertOrigin {
        self.origin
    }

    /// Returns the assigned description.
    #[must_use]
    pub const fn description(self) -> AlertDescription {
        self.description
    }

    /// Returns the semantic outcome class.
    #[must_use]
    pub const fn class(self) -> AlertClass {
        self.description.class()
    }

    /// Returns the hardened semantic severity.
    #[must_use]
    pub const fn severity(self) -> AlertSeverity {
        self.description.severity()
    }
}
