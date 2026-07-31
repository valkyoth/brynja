//! Alert registry and version-admission tests.

use brynja_core::{
    Alert, AlertClass, AlertCode, AlertDescription, AlertOrigin, AlertSeverity, ProtocolVersion,
};

const ASSIGNED: [AlertDescription; 30] = [
    AlertDescription::CloseNotify,
    AlertDescription::UnexpectedMessage,
    AlertDescription::BadRecordMac,
    AlertDescription::RecordOverflow,
    AlertDescription::HandshakeFailure,
    AlertDescription::BadCertificate,
    AlertDescription::UnsupportedCertificate,
    AlertDescription::CertificateRevoked,
    AlertDescription::CertificateExpired,
    AlertDescription::CertificateUnknown,
    AlertDescription::IllegalParameter,
    AlertDescription::UnknownCa,
    AlertDescription::AccessDenied,
    AlertDescription::DecodeError,
    AlertDescription::DecryptError,
    AlertDescription::TooManyCidsRequested,
    AlertDescription::ProtocolVersion,
    AlertDescription::InsufficientSecurity,
    AlertDescription::InternalError,
    AlertDescription::InappropriateFallback,
    AlertDescription::UserCanceled,
    AlertDescription::MissingExtension,
    AlertDescription::UnsupportedExtension,
    AlertDescription::UnrecognizedName,
    AlertDescription::BadCertificateStatusResponse,
    AlertDescription::UnknownPskIdentity,
    AlertDescription::CertificateRequired,
    AlertDescription::GeneralError,
    AlertDescription::NoApplicationProtocol,
    AlertDescription::EchRequired,
];

#[test]
fn registry() {
    for description in ASSIGNED {
        assert_eq!(
            AlertCode::classify(description.code()),
            AlertCode::Assigned(description)
        );
    }

    for code in [21_u8, 30, 41, 60, 100, 111, 114] {
        assert_eq!(AlertCode::classify(code), AlertCode::Reserved(code));
    }

    let classified = (u8::MIN..=u8::MAX).map(AlertCode::classify).count();
    assert_eq!(classified, 256);
    assert_eq!(AlertCode::classify(255), AlertCode::Unassigned(255));
}

#[test]
fn version_matrix_is_fail_closed() {
    assert!(
        Alert::new(
            ProtocolVersion::Dtls13,
            AlertOrigin::Local,
            AlertDescription::TooManyCidsRequested,
        )
        .is_some()
    );
    assert!(
        Alert::new(
            ProtocolVersion::Tls13,
            AlertOrigin::Local,
            AlertDescription::TooManyCidsRequested,
        )
        .is_none()
    );
    assert!(
        Alert::new(
            ProtocolVersion::Tls12,
            AlertOrigin::Local,
            AlertDescription::EchRequired,
        )
        .is_none()
    );
    assert!(
        Alert::new(
            ProtocolVersion::Tls13,
            AlertOrigin::Local,
            AlertDescription::InappropriateFallback,
        )
        .is_none()
    );
}

#[test]
fn severity_is_not_caller_selectable() {
    assert_eq!(AlertDescription::CloseNotify.class(), AlertClass::Closure);
    assert_eq!(
        AlertDescription::UserCanceled.class(),
        AlertClass::Cancellation
    );
    assert_eq!(
        AlertDescription::DecodeError.severity(),
        AlertSeverity::Fatal
    );
    assert_eq!(
        AlertDescription::CloseNotify.severity(),
        AlertSeverity::Warning
    );
}
