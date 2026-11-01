//! Public bounds only: not a proof of HKDF, HMAC, zeroization or constant time.
#![no_std]
#![forbid(unsafe_code)]
#![allow(dead_code)]

// Compile production predicates directly, not copied proof-only equivalents.
#[path = "../../../crates/brynja-legacy-hkdf/src/policy.rs"]
mod legacy;
#[path = "../../../crates/brynja-crypto/src/hkdf/parameters.rs"]
mod modern;

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn modern_output_admission_and_minimal_block_count() {
        let selector: u8 = kani::any();
        kani::assume(selector < 4);
        let width = match selector {
            0 => 28_usize,
            1 => 32,
            2 => 48,
            _ => 64,
        };
        let length: usize = kani::any();
        let plan = modern::ExpansionLength::new(width, length);
        assert_eq!(plan.is_ok(), length <= 255 * width);
        if let Ok(plan) = plan {
            assert_eq!(plan.bytes(), length);
            let blocks = usize::from(plan.blocks());
            assert_eq!(blocks == 0, length == 0);
            assert!(blocks * width >= length);
            if blocks != 0 {
                assert!((blocks - 1) * width < length);
            }
        }
    }

    #[kani::proof]
    fn modern_invalid_width_never_admitted() {
        let width: usize = kani::any();
        let length: usize = kani::any();
        kani::assume(width == 0 || width > usize::MAX / 255);
        assert_eq!(
            modern::ExpansionLength::new(width, length),
            Err(modern::ParameterError::HashLength)
        );
    }

    #[kani::proof]
    #[kani::unwind(2)]
    fn modern_tls_field_admission_and_encoded_size() {
        let label_length: usize = kani::any();
        let context_length: usize = kani::any();
        let output_length: usize = kani::any();
        kani::assume(label_length <= 250);
        kani::assume(context_length <= 256);
        let label = [0x42; 250];
        let context = [0x81; 256];
        let result = modern::Tls13Label::new(
            &label[..label_length],
            &context[..context_length],
            output_length,
        );
        assert_eq!(
            result.is_ok(),
            (1..=249).contains(&label_length) && context_length <= 255 && output_length <= 65535
        );
        if let Ok(label) = result {
            assert_eq!(label.encoded_len(), label_length + context_length + 10);
            assert!(label.encoded_len() <= 514);
        }
    }

    #[kani::proof]
    #[kani::unwind(17)]
    fn modern_short_tls_destination_is_unchanged() {
        let label = modern::Tls13Label::new(b"key", b"abc", kani::any::<u16>() as usize).unwrap();
        assert_eq!(label.encoded_len(), 16);
        let capacity: usize = kani::any();
        kani::assume(capacity < 16);
        let mut destination: [u8; 16] = kani::any();
        let before = destination;
        assert_eq!(
            label.encode(&mut destination[..capacity]),
            Err(modern::ParameterError::DestinationLength)
        );
        assert_eq!(destination, before);
    }

    #[kani::proof]
    fn legacy_output_admission_and_minimal_block_count() {
        let length: usize = kani::any();
        let blocks = legacy::expansion_blocks(length);
        assert_eq!(blocks.is_some(), length <= 5100);
        if let Some(blocks) = blocks {
            let blocks = usize::from(blocks);
            assert_eq!(blocks == 0, length == 0);
            assert!(blocks * 20 >= length);
            if blocks != 0 {
                assert!((blocks - 1) * 20 < length);
            }
        }
    }
}
