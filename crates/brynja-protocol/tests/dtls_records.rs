//! DTLS datagram record-framing tests.

use brynja_core::ProtocolVersion;
use brynja_protocol::{
    ContentType, ContentTypeCode, Dtls12Ciphertext, Dtls13Ciphertext, Dtls13CiphertextConfig,
    Dtls13CiphertextHeader, Dtls13Sequence, DtlsPlaintext, LegacyRecordVersion, RecordError,
    WirePolicy, encode_dtls13_ciphertext,
};

fn plaintext_wire(
    content_type: u8,
    version: [u8; 2],
    epoch: u16,
    sequence: [u8; 6],
    fragment: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(content_type);
    bytes.extend_from_slice(&version);
    bytes.extend_from_slice(&epoch.to_be_bytes());
    bytes.extend_from_slice(&sequence);
    if let Ok(length) = u16::try_from(fragment.len()) {
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(fragment);
    }
    bytes
}

#[test]
fn dtls13_plaintext_ignores_version_but_requires_epoch_zero() {
    let policy = WirePolicy::for_version(ProtocolVersion::Dtls13);
    let bytes = plaintext_wire(22, [0xaa, 0x55], 0, [1, 2, 3, 4, 5, 6], &[9]);
    let parsed = DtlsPlaintext::parse(policy, &bytes);
    assert!(parsed.is_ok());
    if let Ok((record, remaining)) = parsed {
        assert_eq!(record.content_type(), ContentType::Handshake);
        assert_eq!(record.legacy_record_version().bytes(), [0xaa, 0x55]);
        assert_eq!(record.epoch(), 0);
        assert_eq!(record.sequence_number(), [1, 2, 3, 4, 5, 6]);
        assert_eq!(record.fragment(), &[9]);
        assert!(remaining.is_empty());
        let mut output = [0_u8; 14];
        assert_eq!(record.encode(&mut output), Ok(14));
        assert_eq!(output.as_slice(), bytes.as_slice());
    }
    assert!(matches!(
        DtlsPlaintext::parse(policy, &plaintext_wire(22, [254, 253], 1, [0; 6], &[1])),
        Err(RecordError::InvalidPlaintextEpoch)
    ));
}

#[test]
fn dtls_plaintext_construction_is_profile_bound_and_checked() {
    let policy = WirePolicy::for_version(ProtocolVersion::Dtls13);
    let record = DtlsPlaintext::new(
        policy,
        ContentTypeCode::classify(26),
        LegacyRecordVersion::from_bytes([254, 253]),
        0,
        [0, 0, 0, 0, 0, 7],
        &[1, 2],
    );
    assert!(record.is_ok());
    assert!(matches!(
        DtlsPlaintext::new(
            policy,
            ContentTypeCode::classify(22),
            LegacyRecordVersion::from_bytes([254, 252]),
            0,
            [0; 6],
            &[1],
        ),
        Err(RecordError::InvalidPlaintextVersion)
    ));
    assert!(matches!(
        DtlsPlaintext::new(
            policy,
            ContentTypeCode::classify(23),
            LegacyRecordVersion::from_bytes([254, 253]),
            0,
            [0; 6],
            &[1],
        ),
        Err(RecordError::UnsupportedContentType)
    ));
    assert!(matches!(
        DtlsPlaintext::new(
            WirePolicy::for_version(ProtocolVersion::Tls13),
            ContentTypeCode::classify(22),
            LegacyRecordVersion::from_bytes([254, 253]),
            0,
            [0; 6],
            &[1],
        ),
        Err(RecordError::ProfileMismatch)
    ));
}

#[test]
fn dtls12_ciphertext_has_the_tls12_bound_and_preserves_header() {
    let policy = WirePolicy::for_version(ProtocolVersion::Dtls12);
    let fragment = vec![3_u8; (1 << 14) + 2_048];
    let bytes = plaintext_wire(23, [254, 253], 9, [1, 2, 3, 4, 5, 6], &fragment);
    let parsed = Dtls12Ciphertext::parse(policy, &bytes);
    assert!(parsed.is_ok());
    if let Ok((record, remaining)) = parsed {
        assert_eq!(record.epoch(), 9);
        assert_eq!(record.fragment(), fragment.as_slice());
        assert!(remaining.is_empty());
        let mut output = vec![0_u8; record.encoded_len()];
        assert_eq!(record.encode(&mut output), Ok(bytes.len()));
        assert_eq!(output, bytes);
    }
    let oversized = vec![3_u8; (1 << 14) + 2_049];
    assert!(matches!(
        Dtls12Ciphertext::parse(
            policy,
            &plaintext_wire(23, [254, 253], 0, [0; 6], &oversized)
        ),
        Err(RecordError::RecordOverflow)
    ));
}

#[test]
fn dtls13_unified_header_parses_every_layout_dimension() {
    let policy = WirePolicy::for_version(ProtocolVersion::Dtls13);
    let config = Dtls13CiphertextConfig::new(2);
    assert!(config.is_ok());
    if let Ok(config) = config {
        let bytes = [0x3e, 0xaa, 0xbb, 0x01, 0x02, 0x00, 0x03, 7, 8, 9, 0xcc];
        let parsed = Dtls13Ciphertext::parse(policy, config, &bytes);
        assert!(parsed.is_ok());
        if let Ok((record, remaining)) = parsed {
            assert_eq!(record.unified_header(), &[0x3e, 0xaa, 0xbb, 1, 2, 0, 3]);
            assert_eq!(record.connection_id(), &[0xaa, 0xbb]);
            assert_eq!(record.sequence(), Dtls13Sequence::Long(0x0102));
            assert_eq!(record.epoch_bits(), 2);
            assert!(record.length_present());
            assert_eq!(record.encrypted_record(), &[7, 8, 9]);
            assert_eq!(remaining, &[0xcc]);
        }
    }

    if let Ok(no_cid) = Dtls13CiphertextConfig::new(0) {
        let bytes = [0x21, 7, 1, 2, 3];
        let parsed = Dtls13Ciphertext::parse(policy, no_cid, &bytes);
        assert!(parsed.is_ok());
        if let Ok((record, remaining)) = parsed {
            assert_eq!(record.sequence(), Dtls13Sequence::Short(7));
            assert!(!record.length_present());
            assert_eq!(record.encrypted_record(), &[1, 2, 3]);
            assert!(remaining.is_empty());
        }
    }
}

#[test]
fn dtls13_unified_header_encoding_is_transactional_and_round_trips() {
    let header = Dtls13CiphertextHeader::new(3, &[0xaa, 0xbb], Dtls13Sequence::Long(0x1234), true);
    assert!(header.is_ok());
    if let Ok(header) = header {
        let mut output = [0_u8; 10];
        assert_eq!(
            encode_dtls13_ciphertext(header, &[4, 5, 6], &mut output),
            Ok(10)
        );
        if let Ok(config) = Dtls13CiphertextConfig::new(2) {
            let parsed = Dtls13Ciphertext::parse(
                WirePolicy::for_version(ProtocolVersion::Dtls13),
                config,
                &output,
            );
            assert!(parsed.is_ok());
            if let Ok((record, remaining)) = parsed {
                assert_eq!(record.epoch_bits(), 3);
                assert_eq!(record.sequence(), Dtls13Sequence::Long(0x1234));
                assert_eq!(record.encrypted_record(), &[4, 5, 6]);
                assert!(remaining.is_empty());
            }
        }
        for length in 0..output.len() {
            let mut short = vec![0xa5_u8; length];
            let before = short.clone();
            assert_eq!(
                encode_dtls13_ciphertext(header, &[4, 5, 6], &mut short),
                Err(RecordError::InsufficientOutput)
            );
            assert_eq!(short, before);
        }
    }
}

#[test]
fn dtls13_rejects_bad_fixed_bits_cid_context_empty_and_overflow() {
    let policy = WirePolicy::for_version(ProtocolVersion::Dtls13);
    if let Ok(no_cid) = Dtls13CiphertextConfig::new(0) {
        assert!(matches!(
            Dtls13Ciphertext::parse(policy, no_cid, &[0x40, 0, 1]),
            Err(RecordError::InvalidUnifiedHeader)
        ));
        assert!(matches!(
            Dtls13Ciphertext::parse(policy, no_cid, &[0x30, 0, 0, 1, 7]),
            Err(RecordError::ConnectionIdMismatch)
        ));
        assert!(matches!(
            Dtls13Ciphertext::parse(policy, no_cid, &[0x24, 0, 0, 0]),
            Err(RecordError::EmptyFragment)
        ));
        assert!(matches!(
            Dtls13Ciphertext::parse(policy, no_cid, &[0x24, 0, 0x41, 0x01]),
            Err(RecordError::RecordOverflow)
        ));
    }
    assert!(matches!(
        Dtls13CiphertextConfig::new(256),
        Err(RecordError::ConnectionIdTooLong)
    ));
}

#[test]
fn every_dtls_header_truncation_and_heartbeat_content_is_rejected() {
    let policy = WirePolicy::for_version(ProtocolVersion::Dtls13);
    let bytes = plaintext_wire(22, [254, 253], 0, [0, 0, 0, 0, 0, 1], &[1, 2]);
    for cut in 0..bytes.len() {
        if let Some(prefix) = bytes.get(..cut) {
            assert!(matches!(
                DtlsPlaintext::parse(policy, prefix),
                Err(RecordError::Truncated)
            ));
        }
    }
    for version in [ProtocolVersion::Dtls12, ProtocolVersion::Dtls13] {
        assert!(matches!(
            DtlsPlaintext::parse(WirePolicy::for_version(version), &[24]),
            Err(RecordError::HeartbeatRejected)
        ));
    }
}
