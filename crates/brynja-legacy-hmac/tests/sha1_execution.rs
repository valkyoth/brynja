//! Explicit native tests never treat missing authority as successful execution.
#![cfg(feature = "sha1-execution")]
use brynja_legacy_hmac::execution::{Sha1Executor, Sha1Hmac, Sha1Mode};
use brynja_legacy_hmac::{BitString, Error, Hmac, LegacyUse, Sha1};

mod support;

#[test]
fn portable_executor_is_not_accelerated_authority() {
    let owner = Sha1Executor::portable();
    for key in [b"".as_slice(), &[0xa5; 80]] {
        assert!(matches!(
            Sha1Hmac::new(LegacyUse::acknowledge(), &owner, key),
            Err(Error::ExecutionUnavailable)
        ));
    }
    assert!(matches!(
        Sha1Hmac::with_tag_length(LegacyUse::acknowledge(), &owner, b"key", 9),
        Err(Error::TagLength)
    ));
}

#[test]
#[ignore = "requires explicit SHA-NI / Arm SHA1 native driver and full target bundle"]
fn native_sha1_byte_and_bit_composition() -> Result<(), Error> {
    println!();
    let owner = Sha1Executor::for_compiled_target(Sha1Mode::Require)
        .map_err(|_| Error::ExecutionUnavailable)?;
    for key_length in [0, 1, 63, 64, 65, 80, 1024] {
        let key = support::key(key_length);
        for length in [0, 1, 55, 56, 63, 64, 65, 127, 128, 4096] {
            let message = support::message(length);
            let mut expected = [0; 20];
            let _ = Hmac::<Sha1>::authenticate(
                LegacyUse::acknowledge(),
                &key,
                &message,
                &mut expected,
            )?;
            for width in 10..=20 {
                let mut state =
                    Sha1Hmac::with_tag_length(LegacyUse::acknowledge(), &owner, &key, width)?;
                assert_eq!(Some(state.backend()), owner.report().backend);
                state.update(&[])?;
                for part in message.chunks(7) {
                    state.update(part)?;
                }
                let mut output = vec![0xa5; width];
                assert_eq!(
                    state.finalize_tag(&mut output)?.as_bytes(),
                    expected.get(..width).ok_or(Error::TagLength)?
                );
                let mut verifier =
                    Sha1Hmac::with_tag_length(LegacyUse::acknowledge(), &owner, &key, width)?;
                verifier.update(&message)?;
                assert!(verifier.verify(&output)?.expose_public());
                // Every byte position must contribute to the decision.
                for index in 0..width {
                    let mut wrong = output.clone();
                    *wrong.get_mut(index).ok_or(Error::TagLength)? ^= 1;
                    let mut reject =
                        Sha1Hmac::with_tag_length(LegacyUse::acknowledge(), &owner, &key, width)?;
                    reject.update(&message)?;
                    assert!(!reject.verify(&wrong)?.expose_public());
                }
            }
            print!("LEGACY_SHA1_BYTE:{key_length}:{length}:");
            for byte in expected {
                print!("{byte:02x}");
            }
            println!();
        }
    }
    for key_length in [0, 64, 65, 129] {
        let key = vec![0xa7; key_length];
        for bits in [
            0_usize, 1, 2, 3, 4, 5, 6, 7, 8, 9, 447, 448, 449, 503, 504, 505, 511, 512, 513, 1023,
            1024, 1025,
        ] {
            let length = bits.checked_add(7).ok_or(Error::MessageTooLong)? / 8;
            let remainder = bits % 8;
            let valid = if bits == 0 {
                0
            } else if remainder == 0 {
                8
            } else {
                u8::try_from(remainder).map_err(|_| Error::MessageTooLong)?
            };
            let mut message = vec![0xa5; length];
            if remainder != 0 {
                *message.last_mut().ok_or(Error::MessageTooLong)? &= 0xff_u8
                    .checked_shl(
                        8_u32
                            .checked_sub(u32::from(valid))
                            .ok_or(Error::MessageTooLong)?,
                    )
                    .ok_or(Error::MessageTooLong)?;
            }
            let tail = BitString::new(&message, valid).map_err(|_| Error::SecretMemory)?;
            let mut expected = [0; 20];
            let _ = Hmac::<Sha1>::new(LegacyUse::acknowledge(), &key)?
                .finalize_bits_tag(tail, &mut expected)?;
            for split in [0, length.saturating_sub(1) / 2, length.saturating_sub(1)] {
                let prefix = message.get(..split).ok_or(Error::MessageTooLong)?;
                let suffix =
                    BitString::new(message.get(split..).ok_or(Error::MessageTooLong)?, valid)
                        .map_err(|_| Error::SecretMemory)?;
                let mut state = Sha1Hmac::new(LegacyUse::acknowledge(), &owner, &key)?;
                state.update(prefix)?;
                let mut output = [0xa5; 20];
                {
                    let tag = state.finalize_bits_secret(suffix, &mut output)?;
                    assert_eq!(tag.expose(), expected);
                }
                assert_eq!(output, [0; 20]);
                let mut public = Sha1Hmac::new(LegacyUse::acknowledge(), &owner, &key)?;
                public.update(prefix)?;
                assert_eq!(
                    public.finalize_bits_tag(suffix, &mut output)?.as_bytes(),
                    expected
                );
                let mut verifier =
                    Sha1Hmac::with_tag_length(LegacyUse::acknowledge(), &owner, &key, 10)?;
                verifier.update(prefix)?;
                assert!(
                    verifier
                        .verify_bits(suffix, expected.get(..10).ok_or(Error::TagLength)?)?
                        .expose_public()
                );
            }
            print!("LEGACY_SHA1_BITS:{key_length}:{bits}:");
            for byte in expected {
                print!("{byte:02x}");
            }
            println!();
        }
    }
    println!("LEGACY_SHA1_EXECUTION: 70 byte cases, 88 bit cases; no fallback");
    Ok(())
}

#[test]
#[ignore = "requires explicit native SHA-1 execution driver"]
fn native_sha1_revocation_and_output_transactions() -> Result<(), Error> {
    println!();
    for output_length in 0..=21 {
        if output_length == 20 {
            continue;
        }
        let owner = Sha1Executor::for_compiled_target(Sha1Mode::Require)
            .map_err(|_| Error::ExecutionUnavailable)?;
        let mut output = vec![0xa5; output_length];
        let state = Sha1Hmac::new(LegacyUse::acknowledge(), &owner, b"key")?;
        assert!(matches!(
            state.finalize_tag(&mut output),
            Err(Error::TagLength)
        ));
        assert!(output.iter().all(|byte| *byte == 0xa5));
        let state = Sha1Hmac::new(LegacyUse::acknowledge(), &owner, b"key")?;
        assert!(matches!(
            state.finalize_secret(&mut output),
            Err(Error::TagLength)
        ));
        assert!(output.iter().all(|byte| *byte == 0));
        assert!(matches!(
            Sha1Hmac::new(LegacyUse::acknowledge(), &owner, b"key")?.verify(&output),
            Err(Error::TagLength)
        ));
        Sha1Hmac::new(LegacyUse::acknowledge(), &owner, b"key")?.cancel();
    }
    for after_update in [false, true] {
        for operation in 0..5 {
            let owner = Sha1Executor::for_compiled_target(Sha1Mode::Require)
                .map_err(|_| Error::ExecutionUnavailable)?;
            let mut state = Sha1Hmac::new(LegacyUse::acknowledge(), &owner, &[0xa7; 80])?;
            state.update(b"buffered-secret")?;
            owner.quarantine();
            if after_update {
                assert_eq!(state.update(&[]), Err(Error::ExecutionFailed));
                assert_eq!(state.update(b"retry"), Err(Error::ExecutionFailed));
            }
            let tail = BitString::new(&[0xa0], 3).map_err(|_| Error::SecretMemory)?;
            let mut output = [0xa5; 20];
            match operation {
                0 => assert!(matches!(
                    state.finalize_tag(&mut output),
                    Err(Error::ExecutionFailed)
                )),
                1 => assert!(matches!(
                    state.finalize_bits_tag(tail, &mut output),
                    Err(Error::ExecutionFailed)
                )),
                2 => {
                    assert!(matches!(
                        state.finalize_secret(&mut output),
                        Err(Error::ExecutionFailed)
                    ));
                    assert_eq!(output, [0; 20]);
                }
                3 => {
                    assert!(matches!(
                        state.finalize_bits_secret(tail, &mut output),
                        Err(Error::ExecutionFailed)
                    ));
                    assert_eq!(output, [0; 20]);
                }
                _ => assert!(matches!(state.verify(&output), Err(Error::ExecutionFailed))),
            }
            if operation < 2 {
                assert_eq!(output, [0xa5; 20]);
            }
            assert!(matches!(
                Sha1Hmac::new(LegacyUse::acknowledge(), &owner, b"retry"),
                Err(Error::ExecutionFailed)
            ));
        }
    }
    println!("LEGACY_SHA1_LIFECYCLE: malformed outputs preserve executor; revocation is terminal");
    Ok(())
}
