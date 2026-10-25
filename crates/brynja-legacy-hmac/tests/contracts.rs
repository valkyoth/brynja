//! Boundary, transaction and ownership behavior independent of the RFC cases.
use brynja_legacy_hmac::{Algorithm, BitString, Error, Hmac, LegacyUse, Md5, Sha1};

fn state<A: Algorithm>(key: &[u8], message: &[u8], width: usize) -> Result<Hmac<A>, Error> {
    let mut state = Hmac::with_tag_length(LegacyUse::acknowledge(), key, width)?;
    state.update(message)?;
    Ok(state)
}

fn boundaries<A: Algorithm>() -> Result<(), Error> {
    for key_length in [0, 1, 63, 64, 65, 80, 1024] {
        let key = vec![0xa7; key_length];
        for message_length in [0, 1, 55, 56, 63, 64, 65, 127, 128] {
            let message = vec![0x39; message_length];
            let mut expected = vec![0; A::TAG_BYTES];
            let _ =
                Hmac::<A>::authenticate(LegacyUse::acknowledge(), &key, &message, &mut expected)?;
            for width in 10..=A::TAG_BYTES {
                let prefix = expected.get(..width).ok_or(Error::TagLength)?;
                let mut fragmented =
                    Hmac::<A>::with_tag_length(LegacyUse::acknowledge(), &key, width)?;
                fragmented.update(&[])?;
                for byte in &message {
                    fragmented.update(core::slice::from_ref(byte))?;
                }
                let mut output = vec![0; width];
                assert_eq!(fragmented.finalize_tag(&mut output)?.as_bytes(), prefix);
                for position in 0..width {
                    let mut wrong = prefix.to_vec();
                    if let Some(byte) = wrong.get_mut(position) {
                        *byte ^= 1;
                    }
                    assert!(matches!(
                        state::<A>(&key, &message, width)?.verify(&wrong),
                        Err(brynja_legacy_hmac::VerificationError::Mismatch(_))
                    ));
                }
            }
        }
    }
    Ok(())
}

fn transactions<A: Algorithm>() -> Result<(), Error> {
    for width in [0, 1, 9, 21, usize::MAX] {
        assert!(matches!(
            Hmac::<A>::with_tag_length(LegacyUse::acknowledge(), b"key", width),
            Err(Error::TagLength)
        ));
    }
    for length in 0..=21 {
        if length == A::TAG_BYTES {
            continue;
        }
        let mut output = vec![0xa5; length];
        assert!(matches!(
            state::<A>(b"key", b"message", A::TAG_BYTES)?.finalize_tag(&mut output),
            Err(Error::TagLength)
        ));
        assert!(output.iter().all(|byte| *byte == 0xa5));
        assert!(matches!(
            state::<A>(b"key", b"message", A::TAG_BYTES)?.finalize_secret(&mut output),
            Err(Error::TagLength)
        ));
        assert!(output.iter().all(|byte| *byte == 0));
        assert!(matches!(
            state::<A>(b"key", b"message", A::TAG_BYTES)?.verify(&output),
            Err(brynja_legacy_hmac::VerificationError::Operation(
                Error::TagLength
            ))
        ));
    }
    state::<A>(b"key", b"cancel", A::TAG_BYTES)?.cancel();
    Ok(())
}

fn byte_tail<A: Algorithm>() -> Result<(), Error> {
    let mut expected = vec![0; A::TAG_BYTES];
    let _ = Hmac::<A>::authenticate(
        LegacyUse::acknowledge(),
        b"key",
        b"prefixsuffix",
        &mut expected,
    )?;
    let tail = BitString::new(b"suffix", 8).map_err(|_| Error::SecretMemory)?;
    let mut output = vec![0; A::TAG_BYTES];
    assert_eq!(
        state::<A>(b"key", b"prefix", A::TAG_BYTES)?
            .finalize_bits_tag(tail, &mut output)?
            .as_bytes(),
        expected
    );
    assert_eq!(
        state::<A>(b"key", b"prefix", A::TAG_BYTES)?.verify_bits(tail, &expected),
        Ok(())
    );
    {
        let tag =
            state::<A>(b"key", b"prefix", A::TAG_BYTES)?.finalize_bits_secret(tail, &mut output)?;
        assert_eq!(tag.expose(), expected);
    }
    assert!(output.iter().all(|byte| *byte == 0));
    Ok(())
}

#[test]
fn md5_key_message_and_verification_boundaries() -> Result<(), Error> {
    boundaries::<Md5>()
}
#[test]
fn sha1_key_message_and_verification_boundaries() -> Result<(), Error> {
    boundaries::<Sha1>()
}
#[test]
fn md5_output_transactions() -> Result<(), Error> {
    transactions::<Md5>()
}
#[test]
fn sha1_output_transactions() -> Result<(), Error> {
    transactions::<Sha1>()
}
#[test]
fn byte_aligned_tails_match_byte_updates() -> Result<(), Error> {
    byte_tail::<Md5>()?;
    byte_tail::<Sha1>()
}

#[test]
fn mismatch_is_error_for_is_ok_and_question_mark() -> Result<(), Error> {
    use brynja_legacy_hmac::VerificationError;
    assert_eq!(
        VerificationError::Mismatch(17_u64).without_report(),
        VerificationError::Mismatch(())
    );
    assert_eq!(
        VerificationError::<u64>::Operation(Error::TagLength).without_report(),
        VerificationError::Operation(Error::TagLength)
    );
    fn authorize<T, E>(result: Result<T, E>) -> Result<bool, E> {
        let _ = result?;
        Ok(true)
    }
    fn check<A: Algorithm>() -> Result<(), Error> {
        for width in 10..=A::TAG_BYTES {
            for bits in [false, true] {
                let tail = BitString::new(&[0xa0], 3).map_err(|_| Error::SecretMemory)?;
                let mut correct = vec![0; width];
                let owner = state::<A>(b"nonuniform key", b"message", width)?;
                if bits {
                    let _ = owner.finalize_bits_tag(tail, &mut correct)?;
                } else {
                    let _ = owner.finalize_tag(&mut correct)?;
                }
                for matches in [true, false] {
                    let mut candidate = correct.clone();
                    if !matches {
                        *candidate.first_mut().ok_or(Error::TagLength)? ^= 1;
                    }
                    let owner = state::<A>(b"nonuniform key", b"message", width)?;
                    let result = if bits {
                        owner.verify_bits(tail, &candidate)
                    } else {
                        owner.verify(&candidate)
                    };
                    assert_eq!(result.is_ok(), matches);
                    assert_eq!(
                        authorize(result),
                        if matches {
                            Ok(true)
                        } else {
                            Err(brynja_legacy_hmac::VerificationError::Mismatch(()))
                        }
                    );
                }
            }
        }
        Ok(())
    }
    check::<Md5>()?;
    check::<Sha1>()
}
