//! Public general SHA-512/t hashing, oracle and classified-output acceptance.
#![cfg(feature = "general-sha512-t")]
use brynja_hash_sha2::*;

fn auth() -> PublicDeclassification {
    PublicDeclassification::acknowledge()
}
fn bytes(text: &str) -> Vec<u8> {
    if text == "-" {
        return Vec::new();
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = pair.first().copied().unwrap_or_default();
            let low = pair.last().copied().unwrap_or_default();
            let digit = |b: u8| {
                if b <= b'9' {
                    b.saturating_sub(b'0')
                } else {
                    b.saturating_sub(b'a').saturating_add(10)
                }
            };
            digit(high).saturating_mul(16).saturating_add(digit(low))
        })
        .collect()
}

#[test]
fn all_parameters_match_independent_byte_and_bit_oracle() -> Result<(), Sha512TError> {
    for row in include_str!("vectors/general-sha512-t-digest.txt").lines() {
        let fields: Vec<_> = row.split_whitespace().collect();
        let t = fields
            .first()
            .and_then(|s| s.parse().ok())
            .ok_or(Sha512TError::InvalidParameter)?;
        let bits: usize = fields
            .get(1)
            .and_then(|s| s.parse().ok())
            .ok_or(Sha512TError::MessageTooLong)?;
        let message = bytes(fields.get(2).copied().unwrap_or_default());
        let expected = bytes(fields.get(3).copied().unwrap_or_default());
        let p = Sha512TBits::new(t)?;
        let tail = u8::try_from(bits % 8).map_err(|_| Sha512TError::MessageTooLong)?;
        let valid = if tail == 0 && !message.is_empty() {
            8
        } else {
            tail
        };
        let input = BitString::new(&message, valid).map_err(|_| Sha512TError::MessageTooLong)?;
        let result = sha512_t_bits(p, input)?;
        assert_eq!(result.as_bytes(), expected, "t={t} bits={bits}");
        assert_eq!(result.parameter(), p);
        assert_eq!(result, Sha512TDigest::from_bytes(p, &expected)?);
        assert_eq!(hardened_sha512_t_bits_public(p, input, auth())?, result);
        let mut output = vec![0xa5; p.output_bytes()];
        {
            let secret = hardened_sha512_t_bits_secret(p, input, &mut output)?;
            assert_eq!(secret.as_bytes(), expected);
            assert_eq!(secret.parameter(), p);
        }
        assert!(output.iter().all(|b| *b == 0));
        let complete = bits / 8;
        let prefix = message
            .get(..complete)
            .ok_or(Sha512TError::MessageTooLong)?;
        let tail_input = BitString::new(message.get(complete..).unwrap_or_default(), tail)
            .map_err(|_| Sha512TError::MessageTooLong)?;
        let mut ordinary = Sha512T::new(p);
        let mut hardened = HardenedSha512T::new(p);
        for chunk in prefix.chunks(19) {
            ordinary.update(chunk)?;
            hardened.update(chunk)?;
        }
        assert_eq!(ordinary.finalize_bits(tail_input)?, result);
        let secret = hardened.finalize_bits_secret(tail_input, &mut output)?;
        assert_eq!(secret.declassify(auth())?, result);
        assert!(output.iter().all(|b| *b == 0));
        if tail == 0 {
            assert_eq!(sha512_t(p, &message)?, result);
            assert_eq!(hardened_sha512_t_public(p, &message, auth())?, result);
            let secret = hardened_sha512_t_secret(p, &message, &mut output)?;
            assert_eq!(secret.as_bytes(), expected);
        }
    }
    Ok(())
}

#[test]
fn dynamic_general_secret_lifecycle() -> Result<(), Sha512TError> {
    for t in [1, 9, 224, 256, 511] {
        let p = Sha512TBits::new(t)?;
        let expected = sha512_t(p, b"abc")?;
        let mut out = vec![0xa5; p.output_bytes()];
        let mut state = HardenedSha512T::new(p);
        state.update(b"abc")?;
        assert_eq!(
            state.finalize_secret(&mut out)?.declassify(auth())?,
            expected
        );
        assert!(out.iter().all(|b| *b == 0));
        let mut state = HardenedSha512T::new(p);
        state.update(b"abc")?;
        assert!(state.check_additional_bytes(u128::MAX).is_err());
        assert!(state.check_additional_bits(u128::MAX).is_err());
        assert_eq!(state.message_bytes(), 3);
        assert_eq!(state.finalize_public(auth())?, expected);
        for len in [0, 1, 2, 27, 28, 32, 63, 64, 65] {
            let mut rejected = vec![0xa5; len];
            if len != p.output_bytes() {
                assert!(matches!(
                    hardened_sha512_t_secret(p, b"secret", &mut rejected),
                    Err(Sha512TError::OutputLength)
                ));
                assert!(rejected.iter().all(|b| *b == 0));
            }
        }
        let mut cancelled = HardenedSha512T::new(p);
        cancelled.update(b"secret")?;
        cancelled.cancel();
    }
    Ok(())
}

#[test]
fn unwind_clears_secret_destination() -> Result<(), Sha512TError> {
    let mut out = [0xa5; 32];
    let p = Sha512TBits::new(256)?;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let secret = hardened_sha512_t_secret(p, b"confidential", &mut out);
        assert!(secret.is_ok());
        std::panic::resume_unwind(Box::new(()));
    }));
    assert!(result.is_err());
    assert_eq!(out, [0; 32]);
    Ok(())
}

#[test]
fn million_byte_named_identity_matches() -> Result<(), Sha512TError> {
    let input = vec![b'a'; 1_000_000];
    let p = Sha512TBits::new(256)?;
    let named = sha512_256(&input).map_err(|_| Sha512TError::MessageTooLong)?;
    assert_eq!(sha512_t(p, &input)?.as_bytes(), named.as_bytes());
    assert_eq!(
        hardened_sha512_t_public(p, &input, auth())?.as_bytes(),
        named.as_bytes()
    );
    Ok(())
}
