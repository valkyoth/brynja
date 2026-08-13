//! Closed registry and Heartbeat exclusion tests.

use brynja_core::ProtocolVersion;
use brynja_protocol::{
    ContentType, ContentTypeClass, ContentTypeCode, HEARTBEAT_EXTENSION_TYPE, RecordError,
    WirePolicy,
};

#[test]
fn every_content_type_byte_is_preserved_without_coercion() {
    for byte in u8::MIN..=u8::MAX {
        let code = ContentTypeCode::classify(byte);
        assert_eq!(code.code(), byte);
        match code.class() {
            ContentTypeClass::Assigned(content_type) => {
                assert_eq!(content_type.code(), byte);
                assert!((20..=26).contains(&byte));
            }
            ContentTypeClass::Unassigned => assert!(!(20..=26).contains(&byte)),
        }
    }
}

#[test]
fn heartbeat_negotiation_is_rejected_by_every_modern_profile() {
    for version in [
        ProtocolVersion::Tls12,
        ProtocolVersion::Tls13,
        ProtocolVersion::Dtls12,
        ProtocolVersion::Dtls13,
    ] {
        let policy = WirePolicy::for_version(version);
        assert_eq!(
            policy.reject_heartbeat_negotiation(HEARTBEAT_EXTENSION_TYPE),
            Err(RecordError::HeartbeatRejected)
        );
        assert_eq!(policy.reject_heartbeat_negotiation(0), Ok(()));
        assert_eq!(policy.version(), version);
    }
}

#[test]
fn inner_content_is_closed_and_heartbeat_is_never_admitted() {
    let heartbeat = ContentTypeCode::classify(ContentType::Heartbeat.code());
    for version in [ProtocolVersion::Tls13, ProtocolVersion::Dtls13] {
        assert_eq!(
            WirePolicy::for_version(version).admit_inner_content_type(heartbeat),
            Err(RecordError::HeartbeatRejected)
        );
    }
    assert_eq!(
        WirePolicy::for_version(ProtocolVersion::Tls13)
            .admit_inner_content_type(ContentTypeCode::classify(23)),
        Ok(ContentType::ApplicationData)
    );
    assert_eq!(
        WirePolicy::for_version(ProtocolVersion::Dtls13)
            .admit_inner_content_type(ContentTypeCode::classify(26)),
        Ok(ContentType::Ack)
    );
    assert_eq!(
        WirePolicy::for_version(ProtocolVersion::Tls12)
            .admit_inner_content_type(ContentTypeCode::classify(23)),
        Err(RecordError::ProfileMismatch)
    );
    assert_eq!(
        WirePolicy::for_version(ProtocolVersion::Tls13)
            .admit_inner_content_type(ContentTypeCode::classify(255)),
        Err(RecordError::UnsupportedContentType)
    );
}
