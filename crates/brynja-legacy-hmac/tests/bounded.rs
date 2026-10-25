//! Bounded interpreter/sanitizer lifecycle sample. Full native matrices remain.
use brynja_legacy_hmac::{Algorithm, BitString, Error, Hmac, LegacyUse, Md5, Sha1};

fn state<A: Algorithm>(key: &[u8]) -> Result<Hmac<A>, Error> {
    let mut owner = Hmac::<A>::with_tag_length(LegacyUse::acknowledge(), key, 10)?;
    owner.update(b"message")?;
    owner.update(&[])?;
    Ok(owner)
}

fn lifecycle<A: Algorithm>(key: &[u8]) -> Result<(), Error> {
    let mut expected = [0u8; 10];
    let _ = state::<A>(key)?.finalize_tag(&mut expected)?;
    assert_eq!(state::<A>(key)?.verify(&expected), Ok(()));
    let mut wrong = expected;
    wrong[9] ^= 1;
    assert!(matches!(
        state::<A>(key)?.verify(&wrong),
        Err(brynja_legacy_hmac::VerificationError::Mismatch(_))
    ));
    let mut secret = [0xa5; 10];
    {
        let tag = state::<A>(key)?.finalize_secret(&mut secret)?;
        assert_eq!(tag.expose(), expected);
    }
    assert_eq!(secret, [0; 10]);
    let mut rejected = [0xa5; 9];
    assert!(matches!(
        state::<A>(key)?.finalize_tag(&mut rejected),
        Err(Error::TagLength)
    ));
    assert_eq!(rejected, [0xa5; 9]);
    assert!(matches!(
        state::<A>(key)?.finalize_secret(&mut rejected),
        Err(Error::TagLength)
    ));
    assert_eq!(rejected, [0; 9]);
    let tail = BitString::new(&[0xa0], 3).map_err(|_| Error::SecretMemory)?;
    let _ = state::<A>(key)?.finalize_bits_tag(tail, &mut expected)?;
    assert_eq!(state::<A>(key)?.verify_bits(tail, &expected), Ok(()));
    state::<A>(key)?.cancel();
    Ok(())
}

#[test]
fn md5_short() -> Result<(), Error> {
    lifecycle::<Md5>(b"key")
}
#[test]
fn sha1_short() -> Result<(), Error> {
    lifecycle::<Sha1>(b"key")
}
#[test]
fn md5_long() -> Result<(), Error> {
    lifecycle::<Md5>(&[0x36; 65])
}
#[test]
fn sha1_long() -> Result<(), Error> {
    lifecycle::<Sha1>(&[0x36; 65])
}

#[test]
fn output_unwind() -> Result<(), Error> {
    for sha1 in [false, true] {
        let mut output = [0xa5; 10];
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<(), Error> {
                if sha1 {
                    let tag = state::<Sha1>(b"key")?.finalize_secret(&mut output)?;
                    assert_eq!(tag.expose().len(), 10);
                    std::panic::resume_unwind(Box::new("intentional output-owner unwind"));
                } else {
                    let tag = state::<Md5>(b"key")?.finalize_secret(&mut output)?;
                    assert_eq!(tag.expose().len(), 10);
                    std::panic::resume_unwind(Box::new("intentional output-owner unwind"));
                }
            }));
        assert!(result.is_err());
        assert_eq!(output, [0; 10]);
    }
    Ok(())
}
