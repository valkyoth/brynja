//! Adversarial public-API acceptance for the complete KMAC family.

use brynja_mac_kmac::{
    Fips202BitString, Fips202Output, Kmac128, KmacPublicDeclassification, KmacTagPolicy, KmacXof128,
};
#[cfg(feature = "conformance-testing")]
use brynja_mac_kmac::{Kmac256, KmacError, KmacKeyPolicy, KmacServiceStatus};

const KEY128: [u8; 16] = [0xA5; 16];
const KEY256: [u8; 32] = [0x5A; 32];

macro_rules! require_some {
    ($value:expr) => {{
        let value = $value;
        assert!(value.is_some());
        let Some(value) = value else { return };
        value
    }};
}

#[test]
#[cfg(feature = "conformance-testing")]
fn production_and_conformance_parameter_domains_are_separate() {
    assert!(matches!(
        Kmac128::new(&[0; 15], b""),
        Err(KmacError::KeyTooShort)
    ));
    assert!(matches!(
        Kmac256::new(&[0; 31], b""),
        Err(KmacError::KeyTooShort)
    ));
    let weak = require_some!(Kmac128::new_conformance(b"", b"").ok());
    assert_eq!(weak.key_policy(), KmacKeyPolicy::ConformanceOnly);
    let mut short = [0_u8; 3];
    let tag = require_some!(weak.finalize_tag_conformance(&mut short).ok());
    assert_eq!(tag.policy(), KmacTagPolicy::ConformanceOnly);
    assert_eq!(tag.service_status(), KmacServiceStatus::NonApproved);
    let mut too_short = [0xA5; 15];
    assert!(matches!(
        Kmac128::new(&KEY128, b"").and_then(|state| state.finalize_tag(&mut too_short)),
        Err(KmacError::TagTooShort)
    ));
    assert_eq!(too_short, [0xA5; 15]);
}

#[test]
fn streaming_and_one_shot_are_identical_at_rate_boundaries() {
    let message = [0x3C; 337];
    let mut streamed = [0_u8; 32];
    let mut state = require_some!(Kmac128::new(&KEY128, b"boundary").ok());
    for chunk in message.chunks(17) {
        assert_eq!(state.update(chunk), Ok(()));
    }
    assert_eq!(state.message_bytes(), 337);
    assert!(state.finalize_tag(&mut streamed).is_ok());
    let mut one_shot = [0_u8; 32];
    assert!(brynja_mac_kmac::kmac128(&KEY128, &message, b"boundary", &mut one_shot).is_ok());
    assert_eq!(streamed, one_shot);
}

#[test]
fn domain_substitution_changes_outputs_and_fixed_is_not_xof_prefix() {
    let message = b"domain-separated input";
    let mut fixed = [0_u8; 32];
    let mut custom = [0_u8; 32];
    let mut xof = [0_u8; 32];
    assert!(brynja_mac_kmac::kmac128(&KEY128, message, b"", &mut fixed).is_ok());
    assert!(brynja_mac_kmac::kmac128(&KEY128, message, b"custom", &mut custom).is_ok());
    assert_eq!(
        brynja_mac_kmac::kmacxof128_public(
            &KEY128,
            message,
            b"",
            &mut xof,
            KmacPublicDeclassification::acknowledge()
        ),
        Ok(())
    );
    assert_ne!(fixed, custom);
    assert_ne!(fixed, xof);
}

#[test]
fn verification_accepts_exact_tag_and_rejects_first_last_and_length_changes() {
    let mut output = [0_u8; 32];
    assert!(brynja_mac_kmac::kmac128(&KEY128, b"message", b"verify", &mut output).is_ok());
    assert!(verify(&output));
    let mut first = output;
    if let Some(byte) = first.first_mut() {
        *byte ^= 1;
    }
    let mut last = output;
    if let Some(byte) = last.last_mut() {
        *byte ^= 1;
    }
    assert!(!verify(&first));
    assert!(!verify(&last));
    assert!(!verify(output.get(..31).unwrap_or_default()));
}

fn verify(candidate: &[u8]) -> bool {
    Kmac128::new(&KEY128, b"verify")
        .and_then(|mut state| {
            state.update(b"message")?;
            state.verify(candidate)
        })
        .map(|decision| decision.expose_public())
        .unwrap_or(false)
}

#[test]
fn arbitrary_bits_are_canonical_and_streaming_xof_tracks_output() {
    let key = require_some!(Fips202BitString::new(&KEY128, 8).ok());
    let custom = require_some!(Fips202BitString::new(&[0b0000_0101], 3).ok());
    let message = require_some!(Fips202BitString::new(&[0b0000_0011], 2).ok());
    let mut tag_bytes = [0xFF; 17];
    let tag = require_some!(
        Kmac128::new_bits(key, custom)
            .and_then(|state| state.finalize_tag_bits(message, &mut tag_bytes, 3))
            .ok()
    );
    assert_eq!(tag.bit_len(), 131);
    assert_eq!(tag.policy(), KmacTagPolicy::FullStrength);
    assert_eq!(tag.as_bytes().last().copied().unwrap_or_default() & 0xF8, 0);
    let mut reader = require_some!(
        KmacXof128::new(&KEY128, b"bits")
            .and_then(KmacXof128::finalize_xof)
            .ok()
    );
    let mut first = [0_u8; 7];
    assert!(
        reader
            .squeeze_public(&mut first, KmacPublicDeclassification::acknowledge())
            .is_ok()
    );
    assert_eq!(reader.output_bytes(), 7);
    assert_eq!(reader.check_additional_bytes(9), Ok(()));
    let mut tail = [0xFF; 2];
    let destination = require_some!(Fips202Output::new(&mut tail, 5).ok());
    assert!(
        reader
            .squeeze_final_bits_public(destination, KmacPublicDeclassification::acknowledge())
            .is_ok()
    );
    assert_eq!(tail.last().copied().unwrap_or_default() & 0xE0, 0);
}

#[test]
fn secret_output_is_cleared_when_ownership_ends() {
    let mut output = [0_u8; 32];
    {
        let mut state = require_some!(Kmac128::new(&KEY128, b"secret").ok());
        assert_eq!(state.update(&KEY256), Ok(()));
        let secret = require_some!(state.finalize_secret(&mut output).ok());
        assert!(secret.expose().iter().any(|value| *value != 0));
    }
    assert_eq!(output, [0; 32]);
}
