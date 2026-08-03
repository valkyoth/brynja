//! RFC 9850 encoding and production-isolation boundary tests.

use brynja_test_support::{KeyLogError, KeyLogLabel, LineEnding, write_line};

const LABELS: [KeyLogLabel; 10] = [
    KeyLogLabel::ClientRandom,
    KeyLogLabel::ClientEarlyTrafficSecret,
    KeyLogLabel::EarlyExporterSecret,
    KeyLogLabel::ClientHandshakeTrafficSecret,
    KeyLogLabel::ServerHandshakeTrafficSecret,
    KeyLogLabel::ClientTrafficSecret0,
    KeyLogLabel::ServerTrafficSecret0,
    KeyLogLabel::ExporterSecret,
    KeyLogLabel::EchSecret,
    KeyLogLabel::EchConfig,
];

fn expected_length(label: KeyLogLabel, secret_len: usize, ending_len: usize) -> usize {
    let secret_hex = match secret_len.checked_mul(2) {
        Some(value) => value,
        None => return 0,
    };
    let total = label
        .as_bytes()
        .len()
        .checked_add(1)
        .and_then(|value| value.checked_add(64))
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(secret_hex))
        .and_then(|value| value.checked_add(ending_len));
    total.unwrap_or_default()
}

#[test]
fn every_pinned_label_encodes_one_exact_line() {
    let client_random = [0xab; 32];
    let secret = [0x01, 0x2f, 0xa0, 0xff];
    for label in LABELS {
        for (ending, ending_len) in [
            (LineEnding::Lf, 1_usize),
            (LineEnding::CrLf, 2_usize),
            (LineEnding::Cr, 1_usize),
        ] {
            let mut output = [0x55; 160];
            let expected = expected_length(label, secret.len(), ending_len);
            let line = write_line(label, &client_random, &secret, ending, &mut output);
            let line = match line {
                Ok(value) => value,
                Err(_) => {
                    return assert!(core::hint::black_box(false), "valid key-log line failed");
                }
            };
            assert_eq!(line.len(), expected);
            assert!(line.starts_with(label.as_bytes()));
            assert!(line.windows(64).any(|value| value
                == b"ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB"));
            assert!(line.windows(8).any(|value| value == b"012FA0FF"));
            assert!(output.iter().skip(expected).all(|byte| *byte == 0x55));
        }
    }
}

#[test]
fn canonical_example_has_single_spaces_and_uppercase_hex() {
    let client_random = [0x00; 32];
    let secret = [0xab, 0xcd];
    let mut output = [0x33; 100];
    let line = write_line(
        KeyLogLabel::ClientRandom,
        &client_random,
        &secret,
        LineEnding::Lf,
        &mut output,
    );
    let line = match line {
        Ok(value) => value,
        Err(_) => return assert!(core::hint::black_box(false)),
    };
    assert_eq!(
        line,
        b"CLIENT_RANDOM 0000000000000000000000000000000000000000000000000000000000000000 ABCD\n"
    );
}

#[test]
fn reject_invalid_and_exhausted() {
    let client_random = [0xa5; 32];
    let secret = [0x5a; 8];
    let needed = expected_length(KeyLogLabel::ExporterSecret, secret.len(), 2);
    for capacity in 0_usize..needed {
        let mut output = [0x7c; 128];
        let destination = match output.get_mut(..capacity) {
            Some(value) => value,
            None => return assert!(core::hint::black_box(false)),
        };
        let result = write_line(
            KeyLogLabel::ExporterSecret,
            &client_random,
            &secret,
            LineEnding::CrLf,
            destination,
        );
        assert!(matches!(result, Err(KeyLogError::OutputTooSmall)));
        assert!(output.iter().all(|byte| *byte == 0x7c));
    }
}

#[test]
fn empty_secrets_fail_before_output_mutation() {
    let client_random = [0; 32];
    let mut output = [0x42; 96];
    let result = write_line(
        KeyLogLabel::ClientRandom,
        &client_random,
        &[],
        LineEnding::Lf,
        &mut output,
    );
    assert!(matches!(result, Err(KeyLogError::EmptySecret)));
    assert!(output.iter().all(|byte| *byte == 0x42));
}

#[test]
fn keylog_types_are_closed_and_value_free() {
    assert_eq!(format!("{:?}", KeyLogError::EmptySecret), "EmptySecret");
    assert_eq!(KeyLogLabel::EchConfig.as_bytes(), b"ECH_CONFIG");
    assert!(!core::mem::needs_drop::<KeyLogLabel>());
    assert!(!core::mem::needs_drop::<LineEnding>());
}
