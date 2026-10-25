//! Public synthetic test vectors only; excluded from the published archive.
use brynja_legacy_hmac::{Algorithm, BitString, Error, Hmac, LegacyUse, Md5, Sha1};

mod support;

fn emit<A: Algorithm>(name: &str) -> Result<(), Error> {
    for key_length in [0, 1, 63, 64, 65, 80, 1024] {
        let key = support::key(key_length);
        for message_length in [0, 1, 55, 56, 63, 64, 65, 127, 128, 4096] {
            let message = support::message(message_length);
            let mut output = vec![0; A::TAG_BYTES];
            let tag =
                Hmac::<A>::authenticate(LegacyUse::acknowledge(), &key, &message, &mut output)?;
            print!("LEGACY_HMAC_ORACLE:{name}:{key_length}:{message_length}:");
            for byte in tag.as_bytes() {
                print!("{byte:02x}");
            }
            println!();
        }
    }
    Ok(())
}

fn emit_bits<A: Algorithm>(name: &str) -> Result<(), Error> {
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
                let last = message.last_mut().ok_or(Error::MessageTooLong)?;
                *last &= 0xff_u8
                    .checked_shl(
                        8_u32
                            .checked_sub(u32::from(valid))
                            .ok_or(Error::MessageTooLong)?,
                    )
                    .ok_or(Error::MessageTooLong)?;
            }
            let tail = BitString::new(&message, valid).map_err(|_| Error::SecretMemory)?;
            let mut output = vec![0; A::TAG_BYTES];
            let expected = Hmac::<A>::new(LegacyUse::acknowledge(), &key)?
                .finalize_bits_tag(tail, &mut output)?
                .as_bytes()
                .to_vec();
            for split in [0, length.saturating_sub(1) / 2, length.saturating_sub(1)] {
                let mut state = Hmac::<A>::new(LegacyUse::acknowledge(), &key)?;
                let prefix = message.get(..split).ok_or(Error::MessageTooLong)?;
                let suffix =
                    BitString::new(message.get(split..).ok_or(Error::MessageTooLong)?, valid)
                        .map_err(|_| Error::SecretMemory)?;
                state.update(prefix)?;
                {
                    let tag = state.finalize_bits_secret(suffix, &mut output)?;
                    assert_eq!(tag.expose(), expected);
                }
                assert!(output.iter().all(|byte| *byte == 0));
                let mut verify = Hmac::<A>::with_tag_length(LegacyUse::acknowledge(), &key, 10)?;
                verify.update(prefix)?;
                assert!(
                    verify
                        .verify_bits(suffix, expected.get(..10).ok_or(Error::TagLength)?)?
                        .expose_public()
                );
            }
            print!("LEGACY_HMAC_BITS:{name}:{key_length}:{bits}:");
            for byte in expected {
                print!("{byte:02x}");
            }
            println!();
        }
    }
    Ok(())
}

#[test]
fn independent_oracle_population() -> Result<(), Error> {
    emit::<Md5>("md5")?;
    emit::<Sha1>("sha1")?;
    emit_bits::<Md5>("md5")?;
    emit_bits::<Sha1>("sha1")
}
