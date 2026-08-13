//! TLS stream record-framing tests.

use brynja_core::ProtocolVersion;
use brynja_protocol::{
    ContentType, ContentTypeCode, LegacyRecordVersion, RecordError, TlsCiphertext, TlsPlaintext,
    WirePolicy,
};

fn wire(content_type: u8, version: [u8; 2], fragment: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(content_type);
    bytes.extend_from_slice(&version);
    if let Ok(length) = u16::try_from(fragment.len()) {
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(fragment);
    }
    bytes
}

#[test]
fn tls13_plaintext_ignores_and_preserves_legacy_version() {
    let bytes = wire(22, [0x7a, 0x55], &[1, 2, 3]);
    let policy = WirePolicy::for_version(ProtocolVersion::Tls13);
    let parsed = TlsPlaintext::parse(policy, &bytes);
    assert!(parsed.is_ok());
    if let Ok((record, remaining)) = parsed {
        assert_eq!(record.content_type(), ContentType::Handshake);
        assert_eq!(record.legacy_record_version().bytes(), [0x7a, 0x55]);
        assert_eq!(record.fragment(), &[1, 2, 3]);
        assert!(remaining.is_empty());
        let mut output = [0_u8; 8];
        assert_eq!(record.encode(&mut output), Ok(8));
        assert_eq!(output.as_slice(), bytes.as_slice());
    }
}

#[test]
fn outgoing_tls13_plaintext_allows_only_specified_compatibility_values() {
    let policy = WirePolicy::for_version(ProtocolVersion::Tls13);
    let content_type = ContentTypeCode::classify(22);
    assert!(
        TlsPlaintext::new(
            policy,
            content_type,
            LegacyRecordVersion::tls13_default(),
            &[1],
        )
        .is_ok()
    );
    assert!(
        TlsPlaintext::new(
            policy,
            content_type,
            LegacyRecordVersion::tls13_initial_client_hello(),
            &[1],
        )
        .is_ok()
    );
    assert!(matches!(
        TlsPlaintext::new(
            policy,
            content_type,
            LegacyRecordVersion::from_bytes([3, 4]),
            &[1],
        ),
        Err(RecordError::InvalidPlaintextVersion)
    ));
}

#[test]
fn tls13_ciphertext_requires_both_outer_constants() {
    let policy = WirePolicy::for_version(ProtocolVersion::Tls13);
    assert!(TlsCiphertext::parse(policy, &wire(23, [3, 3], &[7])).is_ok());
    assert!(matches!(
        TlsCiphertext::parse(policy, &wire(22, [3, 3], &[7])),
        Err(RecordError::InvalidCiphertextType)
    ));
    assert!(matches!(
        TlsCiphertext::parse(policy, &wire(23, [3, 1], &[7])),
        Err(RecordError::InvalidCiphertextVersion)
    ));
    assert!(matches!(
        TlsCiphertext::parse(policy, &wire(23, [3, 3], &[])),
        Err(RecordError::EmptyFragment)
    ));
}

#[test]
fn tls12_and_tls13_enforce_distinct_protected_bounds() {
    let tls12 = WirePolicy::for_version(ProtocolVersion::Tls12);
    let tls13 = WirePolicy::for_version(ProtocolVersion::Tls13);
    let tls13_max = vec![1_u8; (1 << 14) + 256];
    assert!(TlsCiphertext::parse(tls13, &wire(23, [3, 3], &tls13_max)).is_ok());
    let tls13_over = vec![1_u8; (1 << 14) + 257];
    assert!(matches!(
        TlsCiphertext::parse(tls13, &wire(23, [3, 3], &tls13_over)),
        Err(RecordError::RecordOverflow)
    ));
    assert!(TlsCiphertext::parse(tls12, &wire(23, [3, 3], &tls13_over)).is_ok());
    let tls12_over = vec![1_u8; (1 << 14) + 2_049];
    assert!(matches!(
        TlsCiphertext::parse(tls12, &wire(23, [3, 3], &tls12_over)),
        Err(RecordError::RecordOverflow)
    ));
}

#[test]
fn plaintext_bounds_empty_rules_and_stream_suffix_are_exact() {
    let policy = WirePolicy::for_version(ProtocolVersion::Tls12);
    assert!(TlsPlaintext::parse(policy, &wire(23, [3, 3], &[])).is_ok());
    assert!(matches!(
        TlsPlaintext::parse(policy, &wire(22, [3, 3], &[])),
        Err(RecordError::EmptyFragment)
    ));
    let maximum = vec![2_u8; 1 << 14];
    assert!(TlsPlaintext::parse(policy, &wire(22, [3, 3], &maximum)).is_ok());
    let oversized = vec![2_u8; (1 << 14) + 1];
    assert!(matches!(
        TlsPlaintext::parse(policy, &wire(22, [3, 3], &oversized)),
        Err(RecordError::RecordOverflow)
    ));
    let mut joined = wire(22, [3, 3], &[1]);
    joined.extend_from_slice(&wire(23, [3, 3], &[2, 3]));
    let first = TlsPlaintext::parse(policy, &joined);
    assert!(first.is_ok());
    if let Ok((record, remaining)) = first {
        assert_eq!(record.fragment(), &[1]);
        let second = TlsPlaintext::parse(policy, remaining);
        assert!(second.is_ok());
        if let Ok((record, remaining)) = second {
            assert_eq!(record.fragment(), &[2, 3]);
            assert!(remaining.is_empty());
        }
    }
}

#[test]
fn every_truncation_and_short_output_is_transactional() {
    let bytes = wire(22, [3, 3], &[1, 2, 3, 4]);
    let policy = WirePolicy::for_version(ProtocolVersion::Tls13);
    for cut in 0..bytes.len() {
        if let Some(prefix) = bytes.get(..cut) {
            assert!(matches!(
                TlsPlaintext::parse(policy, prefix),
                Err(RecordError::Truncated)
            ));
        }
    }
    if let Ok((record, _)) = TlsPlaintext::parse(policy, &bytes) {
        for length in 0..record.encoded_len() {
            let mut output = vec![0xa5_u8; length];
            let before = output.clone();
            assert_eq!(
                record.encode(&mut output),
                Err(RecordError::InsufficientOutput)
            );
            assert_eq!(output, before);
        }
    }
}

#[test]
fn heartbeat_and_unknown_content_fail_before_payload_processing() {
    for version in [ProtocolVersion::Tls12, ProtocolVersion::Tls13] {
        let policy = WirePolicy::for_version(version);
        assert!(matches!(
            TlsPlaintext::parse(policy, &[24]),
            Err(RecordError::HeartbeatRejected)
        ));
        assert!(matches!(
            TlsPlaintext::parse(policy, &[255]),
            Err(RecordError::UnsupportedContentType)
        ));
    }
}
