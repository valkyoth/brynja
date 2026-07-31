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

/// One byte in the TLS AlertDescription registry.
///
/// The byte is private so callers cannot construct a contradictory registry
/// category. Use [`Self::class`] to inspect its exact current classification.
///
/// ```compile_fail
/// let _ = brynja_core::AlertCode(0);
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AlertCode(u8);

/// The current registry category of an [`AlertCode`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AlertCodeClass {
    /// A currently assigned description.
    Assigned(AlertDescription),
    /// An explicitly reserved registry code.
    Reserved,
    /// A currently unassigned registry code.
    Unassigned,
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
        Self(code)
    }

    /// Returns the exact registry byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        self.0
    }

    /// Returns the exact current registry category.
    #[must_use]
    pub const fn class(self) -> AlertCodeClass {
        match self.0 {
            0 => AlertCodeClass::Assigned(AlertDescription::CloseNotify),
            10 => AlertCodeClass::Assigned(AlertDescription::UnexpectedMessage),
            20 => AlertCodeClass::Assigned(AlertDescription::BadRecordMac),
            22 => AlertCodeClass::Assigned(AlertDescription::RecordOverflow),
            40 => AlertCodeClass::Assigned(AlertDescription::HandshakeFailure),
            42 => AlertCodeClass::Assigned(AlertDescription::BadCertificate),
            43 => AlertCodeClass::Assigned(AlertDescription::UnsupportedCertificate),
            44 => AlertCodeClass::Assigned(AlertDescription::CertificateRevoked),
            45 => AlertCodeClass::Assigned(AlertDescription::CertificateExpired),
            46 => AlertCodeClass::Assigned(AlertDescription::CertificateUnknown),
            47 => AlertCodeClass::Assigned(AlertDescription::IllegalParameter),
            48 => AlertCodeClass::Assigned(AlertDescription::UnknownCa),
            49 => AlertCodeClass::Assigned(AlertDescription::AccessDenied),
            50 => AlertCodeClass::Assigned(AlertDescription::DecodeError),
            51 => AlertCodeClass::Assigned(AlertDescription::DecryptError),
            52 => AlertCodeClass::Assigned(AlertDescription::TooManyCidsRequested),
            70 => AlertCodeClass::Assigned(AlertDescription::ProtocolVersion),
            71 => AlertCodeClass::Assigned(AlertDescription::InsufficientSecurity),
            80 => AlertCodeClass::Assigned(AlertDescription::InternalError),
            86 => AlertCodeClass::Assigned(AlertDescription::InappropriateFallback),
            90 => AlertCodeClass::Assigned(AlertDescription::UserCanceled),
            109 => AlertCodeClass::Assigned(AlertDescription::MissingExtension),
            110 => AlertCodeClass::Assigned(AlertDescription::UnsupportedExtension),
            112 => AlertCodeClass::Assigned(AlertDescription::UnrecognizedName),
            113 => AlertCodeClass::Assigned(AlertDescription::BadCertificateStatusResponse),
            115 => AlertCodeClass::Assigned(AlertDescription::UnknownPskIdentity),
            116 => AlertCodeClass::Assigned(AlertDescription::CertificateRequired),
            117 => AlertCodeClass::Assigned(AlertDescription::GeneralError),
            120 => AlertCodeClass::Assigned(AlertDescription::NoApplicationProtocol),
            121 => AlertCodeClass::Assigned(AlertDescription::EchRequired),
            21 | 30 | 41 | 60 | 100 | 111 | 114 => AlertCodeClass::Reserved,
            _ => AlertCodeClass::Unassigned,
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
