use super::*;
extern crate std;
use crate::{Fips202BitString, KmacError};

#[cfg(feature = "conformance-testing")]
#[test]
fn borrowed_verification_rejects_equal_mismatches_across_chunks() -> Result<(), KmacError> {
    macro_rules! check {
        ($name:ident, $workspace:ident) => {{
            let key = Fips202BitString::new(&[0x13], 5).map_err(|_| KmacError::InvalidBitString)?;
            let empty = Fips202BitString::new(&[], 0).map_err(|_| KmacError::InvalidBitString)?;
            let mut workspace = $workspace::new();
            for length in [1, 63, 64, 65, 129] {
                for valid in 1..=8 {
                    let mut storage = [0; 129];
                    let tag = storage
                        .get_mut(..length)
                        .ok_or(KmacError::InvalidBitString)?;
                    let _ = crate::$name::new_bits_conformance(key, empty)?
                        .finalize_tag_bits_conformance(empty, tag, valid)?;
                    for mismatch in [false, true] {
                        if mismatch {
                            *tag.first_mut().ok_or(KmacError::InvalidBitString)? ^= 1;
                            if length > 1 {
                                *tag.last_mut().ok_or(KmacError::InvalidBitString)? ^= 1;
                            }
                        }
                        let candidate = Fips202BitString::new(tag, valid)
                            .map_err(|_| KmacError::InvalidBitString)?;
                        assert_eq!(
                            crate::$name::new_bits_conformance(key, empty)?
                                .verify_bits_conformance(empty, candidate)?
                                .expose_public(),
                            !mismatch
                        );
                        assert_eq!(
                            workspace
                                .with_bits_conformance(key, empty, |state| state
                                    .verify_bits_conformance(empty, candidate))??
                                .expose_public(),
                            !mismatch
                        );
                        assert!(workspace.metadata_cleared());
                        #[cfg(feature = "hardened-execution")]
                        assert_eq!(
                            crate::execution::$name::new_bits_conformance(
                                crate::execution::Mode::Portable,
                                key,
                                empty
                            )?
                            .verify_bits_conformance(empty, candidate)?
                            .expose_public(),
                            !mismatch
                        );
                    }
                }
            }
        }};
    }
    check!(Kmac128, Kmac128Workspace);
    check!(Kmac256, Kmac256Workspace);
    Ok(())
}

#[test]
fn scoped_known_answer_and_returned_secret() -> Result<(), KmacError> {
    let mut workspace = Kmac128Workspace::new();
    let key = [0x42; 16];
    let mut expected = [0; 32];
    let expected = crate::kmac128(&key, b"abc", b"custom", &mut expected)?;
    let mut output = [0xa5; 32];
    let secret = workspace.with(&key, b"custom", |mut state| {
        state.update(b"abc")?;
        state.finalize_secret(&mut output)
    })??;
    assert_eq!(secret.expose(), expected.as_bytes());
    drop(secret);
    assert_eq!(output, [0; 32]);
    Ok(())
}

macro_rules! lifecycle {
    ($workspace:ident, $width:literal) => {{
        let mut workspace = $workspace::new();
        let key = [0x42; 32];
        let mut called = false;
        assert!(matches!(workspace.with(&[], b"", |_| called = true), Err(KmacError::KeyTooShort)));
        assert!(!called);
        for forget in [false, true] {
            workspace.with(&key, b"custom", |mut state| {
                state.update(b"secret")?;
                if forget { core::mem::forget(state); } else { state.cancel(); }
                Ok::<(), KmacError>(())
            })??;
            assert!(workspace.metadata_cleared());
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = workspace.with(&key, b"custom", |state| {
                    if forget { core::mem::forget(state); }
                    std::panic::resume_unwind(std::boxed::Box::new(()));
                });
            }));
            assert!(result.is_err()); assert!(workspace.metadata_cleared());
        }
        for size in [0, 1, $width - 1] {
            let mut bytes = std::vec![0xa5; size];
            assert!(matches!(workspace.with(&key, b"", |state| state.finalize_tag(&mut bytes))?, Err(KmacError::TagTooShort)));
            assert!(bytes.iter().all(|b| *b == 0xa5));
            assert!(matches!(workspace.with(&key, b"", |state| state.finalize_secret(&mut bytes))?, Err(KmacError::TagTooShort)));
            assert!(bytes.iter().all(|b| *b == 0)); assert!(workspace.metadata_cleared());
        }
        for valid in [0, 9, 255] {
            let mut bytes = [0xa5; $width];
            let empty = Fips202BitString::new(&[], 0).map_err(|_| KmacError::InvalidBitString)?;
            assert!(matches!(workspace.with(&key, b"", |state| state.finalize_secret_bits(empty, &mut bytes, valid))?, Err(KmacError::InvalidBitString)));
            assert_eq!(bytes, [0; $width]); assert!(workspace.metadata_cleared());
        }
        let mut tag = [0; 65];
        let _ = workspace.with(&key, b"", |state| state.finalize_tag(&mut tag))??;
        assert!(workspace.with(&key, b"", |state| state.verify(&tag))??.expose_public());
        for index in [0, 32, 64] {
            let byte = tag.get_mut(index).ok_or(KmacError::InvalidBitString)?; *byte ^= 1;
            assert!(!workspace.with(&key, b"", |state| state.verify(&tag))??.expose_public());
            let byte = tag.get_mut(index).ok_or(KmacError::InvalidBitString)?; *byte ^= 1;
            assert!(workspace.metadata_cleared());
        }
        let empty = Fips202BitString::new(&[], 0).map_err(|_| KmacError::InvalidBitString)?;
        let candidate = Fips202BitString::new(&tag, 8).map_err(|_| KmacError::InvalidBitString)?;
        assert!(matches!(workspace.with(&key, b"", |state| state.verify_exact(empty, candidate, 519))?, Err(KmacError::InvalidBitString)));
        assert!(workspace.metadata_cleared());
    }};
}

#[test]
fn scoped_lifecycle_strength_and_verification_failures() -> Result<(), KmacError> {
    lifecycle!(Kmac128Workspace, 16);
    lifecycle!(Kmac256Workspace, 32);
    Ok(())
}

#[cfg(feature = "conformance-testing")]
#[test]
fn scoped_all_bit_domains_match_existing_portable_api() -> Result<(), KmacError> {
    macro_rules! campaign {
        ($workspace:ident, $reference:ident) => {{
            let mut workspace = $workspace::new();
            for length in [0, 1, 135, 136, 167, 168, 169, 337] {
                for valid in 1..=8 {
                    let mut message = std::vec![0x59; length];
                    if let Some(last) = message.last_mut() { *last &= 0xff >> (8 - valid); }
                    let input = Fips202BitString::new(&message, if length == 0 {0} else {valid}).map_err(|_| KmacError::InvalidBitString)?;
                    for output_len in [0, 1, 15, 16, 31, 32, 65] {
                        let output_valid = if output_len == 0 { 0 } else {valid};
                        let key = Fips202BitString::new(&[0x13], 5).map_err(|_| KmacError::InvalidBitString)?;
                        let custom = Fips202BitString::new(&[0x05], 3).map_err(|_| KmacError::InvalidBitString)?;
                        let mut expected = std::vec![0; output_len];
                        let _ = crate::$reference::new_bits_conformance(key, custom)?.finalize_tag_bits_conformance(input, &mut expected, output_valid)?;
                        let mut output = std::vec![0xa5; output_len];
                        let secret = workspace.with_bits_conformance(key, custom, |state| state.finalize_secret_bits_conformance(input, &mut output, output_valid))??;
                        assert_eq!(secret.expose(), expected); drop(secret);
                        assert!(output.iter().all(|b| *b == 0)); assert!(workspace.metadata_cleared());
                        let _ = workspace.with_bits_conformance(key, custom, |mut state| {
                            let prefix = length.saturating_sub(1);
                            for chunk in message.get(..prefix).ok_or(KmacError::InvalidBitString)?.chunks(17) { state.update(chunk)?; }
                            let tail = Fips202BitString::new(message.get(prefix..).ok_or(KmacError::InvalidBitString)?, if length == 0 { 0 } else {valid}).map_err(|_| KmacError::InvalidBitString)?;
                            state.finalize_tag_bits_conformance(tail, &mut output, output_valid)
                        })??;
                        assert_eq!(output, expected);
                        let candidate = Fips202BitString::new(&output, output_valid).map_err(|_| KmacError::InvalidBitString)?;
                        assert!(workspace.with_bits_conformance(key, custom, |state| state.verify_bits_conformance(input, candidate))??.expose_public());
                    }
                }
            }
            let mut output = [0xa5; 32];
            assert!(matches!(workspace.with_conformance(b"", b"", |state| state.finalize_secret(&mut output))?, Err(KmacError::KeyTooShort)));
            assert_eq!(output, [0; 32]);
        }};
    }
    campaign!(Kmac128Workspace, Kmac128);
    campaign!(Kmac256Workspace, Kmac256);
    Ok(())
}
