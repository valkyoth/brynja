//! Scoped HKDF metadata bounds and TLS label framing regressions.

use super::{ExpansionLength, ParameterError, Tls13Label};

#[test]
fn expansion_boundaries_and_exhaustion() -> Result<(), ParameterError> {
    for width in [20_usize, 28, 32, 48, 64] {
        for bytes in [
            0,
            1,
            width.saturating_sub(1),
            width,
            width.saturating_add(1),
            width.saturating_mul(254),
            width.saturating_mul(255),
        ] {
            let plan = ExpansionLength::new(width, bytes)?;
            assert_eq!(plan.bytes(), bytes);
            assert_eq!(usize::from(plan.blocks()), bytes.div_ceil(width));
            assert_eq!(plan.counters().count(), usize::from(plan.blocks()));
            assert!(plan.counters().all(|c| c != 0));
        }
        assert_eq!(
            ExpansionLength::new(width, width.saturating_mul(255).saturating_add(1)),
            Err(ParameterError::ExpansionLength)
        );
        assert_eq!(
            ExpansionLength::new(width, width.saturating_mul(256)),
            Err(ParameterError::ExpansionLength)
        );
        let mut counters = ExpansionLength::new(width, width.saturating_mul(255))?.counters();
        assert_eq!(counters.nth(254), Some(255));
        assert_eq!(counters.next(), None);
        assert_eq!(counters.next(), None);
    }
    Ok(())
}

#[test]
fn invalid_widths_and_usize_extremes_are_checked() -> Result<(), ParameterError> {
    assert_eq!(ExpansionLength::new(0, 0), Err(ParameterError::HashLength));
    assert_eq!(
        ExpansionLength::new(usize::MAX, 0),
        Err(ParameterError::HashLength)
    );
    assert_eq!(
        ExpansionLength::new(32, usize::MAX),
        Err(ParameterError::ExpansionLength)
    );
    let width = usize::MAX / 255;
    assert_eq!(
        ExpansionLength::new(width, width.saturating_mul(255))?.blocks(),
        255
    );
    assert_eq!(
        ExpansionLength::new(width.saturating_add(1), 0),
        Err(ParameterError::HashLength)
    );
    Ok(())
}

#[test]
fn bounded_exhaustive_block_count_matches_independent_model() {
    // Exhaustive finite arithmetic model, not a symbolic proof or HMAC test.
    for width in 1_usize..=64 {
        for bytes in 0..=width.saturating_mul(256) {
            match ExpansionLength::new(width, bytes) {
                Ok(plan) => {
                    assert!(bytes <= width.saturating_mul(255));
                    let blocks = usize::from(plan.blocks());
                    assert!(blocks.saturating_mul(width) >= bytes);
                    assert!(blocks == 0 || blocks.saturating_sub(1).saturating_mul(width) < bytes);
                }
                Err(error) => {
                    assert!(bytes > width.saturating_mul(255));
                    assert_eq!(error, ParameterError::ExpansionLength);
                }
            }
        }
    }
}

#[test]
fn tls_label_exact_wire_bytes() -> Result<(), ParameterError> {
    let mut output = [0xa5; 40];
    let label = Tls13Label::new(b"key", b"", 16)?;
    assert_eq!(label.encoded_len(), 13);
    assert_eq!(label.encode(&mut output)?, b"\x00\x10\x09tls13 key\x00");
    assert_eq!(output.get(13..), Some([0xa5; 27].as_slice()));
    let label = Tls13Label::new(b"derived", b"\x00\x80\xff", 0x1234)?;
    assert_eq!(
        label.encode(&mut output)?,
        b"\x12\x34\x0dtls13 derived\x03\x00\x80\xff"
    );
    Ok(())
}

#[test]
fn tls_label_rejects_invalid_fields_without_mutation() -> Result<(), ParameterError> {
    assert_eq!(
        Tls13Label::new(&[], &[], 0),
        Err(ParameterError::LabelLength)
    );
    assert_eq!(
        Tls13Label::new(&[0; 250], &[], 0),
        Err(ParameterError::LabelLength)
    );
    assert_eq!(
        Tls13Label::new(b"x", &[0; 256], 0),
        Err(ParameterError::ContextLength)
    );
    assert_eq!(
        Tls13Label::new(b"x", &[], 65536),
        Err(ParameterError::TlsOutputLength)
    );
    assert_eq!(
        Tls13Label::new(b"x", &[], usize::MAX),
        Err(ParameterError::TlsOutputLength)
    );
    let label = Tls13Label::new(b"key", b"context", 32)?;
    for capacity in 0..label.encoded_len() {
        let mut output = [0x5a; 32];
        assert_eq!(
            label.encode(
                output
                    .get_mut(..capacity)
                    .ok_or(ParameterError::DestinationLength)?
            ),
            Err(ParameterError::DestinationLength)
        );
        assert_eq!(output, [0x5a; 32]);
    }
    Ok(())
}

#[test]
fn tls_label_maximum_and_disjoint_shared_allocation() -> Result<(), ParameterError> {
    let mut output = [0; 514];
    let label = Tls13Label::new(&[0x81; 249], &[0x42; 255], 65535)?;
    assert_eq!(label.encoded_len(), 514);
    let bytes = label.encode(&mut output)?;
    assert_eq!(bytes.get(..9), Some(b"\xff\xff\xfftls13 ".as_slice()));
    assert_eq!(bytes.get(9..258), Some([0x81; 249].as_slice()));
    assert_eq!(bytes.get(258), Some(&255));
    assert_eq!(bytes.get(259..), Some([0x42; 255].as_slice()));
    let mut shared = [0x31; 32];
    let (input, destination) = shared.split_at_mut(2);
    let (name, context) = input.split_at(1);
    let label = Tls13Label::new(name, context, 0)?;
    assert_eq!(label.encode(destination)?, b"\x00\x00\x07tls13 1\x011");
    assert_eq!(input, b"11");
    Ok(())
}
