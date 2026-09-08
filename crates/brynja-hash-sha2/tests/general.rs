//! Exhaustive general SHA-512/t public descriptor, canonical digest and IV tests.
#![cfg(feature = "general-sha512-t")]

use brynja_hash_sha2::{Sha512TBits, Sha512TDigest, Sha512TError};

#[test]
fn all_u16_parameters_and_all_label_destinations() -> Result<(), Sha512TError> {
    let mut accepted = 0;
    for t in 0..=u16::MAX {
        if t == 0 || t == 384 || t >= 512 {
            assert_eq!(Sha512TBits::new(t), Err(Sha512TError::InvalidParameter));
            assert_eq!(
                Sha512TBits::try_from(t),
                Err(Sha512TError::InvalidParameter)
            );
            continue;
        }
        accepted += 1;
        let parameter = Sha512TBits::new(t)?;
        assert_eq!(parameter.bits(), t);
        assert_eq!(parameter.output_bytes(), usize::from(t).div_ceil(8));
        let expected = format!("SHA-512/{t}");
        for size in 0..=14 {
            let mut buffer = [0xa5; 14];
            let result =
                parameter.write_iv_label(buffer.get_mut(..size).ok_or(Sha512TError::OutputLength)?);
            if size < expected.len() {
                assert_eq!(result, Err(Sha512TError::OutputLength));
                assert_eq!(buffer, [0xa5; 14]);
            } else {
                assert_eq!(result, Ok(expected.len()));
                assert_eq!(buffer.get(..expected.len()), Some(expected.as_bytes()));
                assert_eq!(
                    buffer.get(expected.len()..),
                    [0xa5; 14].get(expected.len()..)
                );
            }
        }
    }
    assert_eq!(accepted, 510);
    Ok(())
}

#[test]
fn all_510_initial_states_match_independent_oracle() -> Result<(), Sha512TError> {
    let mut rows = include_str!("vectors/general-sha512-t-iv.txt").lines();
    for t in (1..512).filter(|t| *t != 384) {
        let parameter = Sha512TBits::new(t)?;
        let expected = rows.next();
        let mut actual = format!("{t}");
        for word in parameter.initial_words() {
            actual.push_str(&format!(" {word:016x}"));
        }
        assert_eq!(Some(actual.as_str()), expected);
    }
    assert_eq!(rows.next(), None);
    Ok(())
}

#[test]
fn named_ivs_and_short_decimal_transitions_are_exact() -> Result<(), Sha512TError> {
    assert_eq!(
        Sha512TBits::new(224)?.initial_words(),
        [
            0x8c3d37c819544da2,
            0x73e1996689dcd4d6,
            0x1dfab7ae32ff9c82,
            0x679dd514582f9fcf,
            0x0f6d2b697bd44da8,
            0x77e36f7304c48942,
            0x3f9d85a86a1d36c8,
            0x1112e6ad91d692a1,
        ]
    );
    assert_eq!(
        Sha512TBits::new(256)?.initial_words(),
        [
            0x22312194fc2bf72c,
            0x9f555fa3c84c64c2,
            0x2393b86b6f53b151,
            0x963877195940eabd,
            0x96283ee2a88effe3,
            0xbe5e1e2553863992,
            0x2b0199fc2c85b8aa,
            0x0eb72ddc81c52ca2,
        ]
    );
    for pair in [(1, 9), (9, 10), (99, 100), (383, 385), (510, 511)] {
        assert_ne!(
            Sha512TBits::new(pair.0)?.initial_words(),
            Sha512TBits::new(pair.1)?.initial_words()
        );
    }
    Ok(())
}

#[test]
fn every_parameter_rejects_wrong_lengths_and_noncanonical_bits() -> Result<(), Sha512TError> {
    for t in (1..512).filter(|t| *t != 384) {
        let parameter = Sha512TBits::new(t)?;
        let length = parameter.output_bytes();
        let mut input = [0; 65];
        for size in 0..=65 {
            let result = Sha512TDigest::from_bytes(
                parameter,
                input.get(..size).ok_or(Sha512TError::OutputLength)?,
            );
            assert_eq!(result.is_ok(), size == length);
            if size != length {
                assert_eq!(result, Err(Sha512TError::OutputLength));
            }
        }
        for byte in 0..=u8::MAX {
            *input
                .get_mut(length - 1)
                .ok_or(Sha512TError::OutputLength)? = byte;
            let result = Sha512TDigest::from_bytes(
                parameter,
                input.get(..length).ok_or(Sha512TError::OutputLength)?,
            );
            let unused = (8 - t % 8) % 8;
            let valid = u16::from(byte) % (1 << unused) == 0;
            assert_eq!(result.is_ok(), valid);
            if valid {
                let digest = result?;
                assert_eq!(digest.parameter(), parameter);
                assert_eq!(Some(digest.as_bytes()), input.get(..length));
                assert_eq!(Some(digest.as_ref()), input.get(..length));
            } else {
                assert_eq!(result, Err(Sha512TError::NonCanonicalOutput));
            }
            assert_eq!(input.get(length - 1), Some(&byte));
        }
    }
    Ok(())
}

#[test]
fn equality_and_hash_include_exact_parameter() -> Result<(), Sha512TError> {
    use std::collections::HashSet;
    let mut values = HashSet::new();
    let mut previous: Option<Sha512TDigest> = None;
    for t in (1..512).filter(|t| *t != 384) {
        let parameter = Sha512TBits::new(t)?;
        let digest = Sha512TDigest::from_bytes(
            parameter,
            [0; 64]
                .get(..parameter.output_bytes())
                .ok_or(Sha512TError::OutputLength)?,
        )?;
        assert!(values.insert(digest));
        assert_eq!(digest, digest);
        if let Some(other) = previous {
            // Exercise Eq directly, not only HashSet buckets: distinct hashes
            // could otherwise conceal an Eq implementation that ignores t.
            assert_ne!(digest, other);
            if digest.as_bytes().len() == other.as_bytes().len() {
                assert_eq!(digest.as_bytes(), other.as_bytes());
            }
        }
        previous = Some(digest);
    }
    assert_eq!(values.len(), 510);
    Ok(())
}

#[test]
fn bounded_public_api_smoke() -> Result<(), Sha512TError> {
    for t in [1, 9, 99, 100, 224, 256, 383, 385, 511] {
        let parameter = Sha512TBits::new(t)?;
        let digest = Sha512TDigest::from_bytes(
            parameter,
            [0; 64]
                .get(..parameter.output_bytes())
                .ok_or(Sha512TError::OutputLength)?,
        )?;
        assert_eq!(digest.as_bytes().len(), parameter.output_bytes());
        let mut output = [0; 11];
        assert!(parameter.write_iv_label(&mut output)? >= 9);
        assert_ne!(parameter.initial_words(), [0; 8]);
    }
    Ok(())
}
