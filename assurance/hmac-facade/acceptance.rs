use api::hmac::*;

#[test]
fn rfc4231_sha256_and_secret_lifecycle() -> Result<(), Error> {
    let expected = [
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
        0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
    ];
    let key = [0x0b; 20];
    let mut output = [0; 32];
    let mut state = Hmac::<Sha256>::new(&key)?;
    state.update(b"Hi There")?;
    let tag = state.finalize_secret(&mut output)?;
    assert_eq!(tag.expose(), expected);
    drop(tag);
    assert_eq!(output, [0; 32]);
    let mut verifier = Hmac::<Sha256>::new(&key)?;
    verifier.update(b"Hi There")?;
    assert_eq!(verifier.verify(&expected), Ok(()));
    Ok(())
}

fn identity<A: Algorithm>() -> Result<(), Error> {
    let key = [0x52; 257];
    let mut output = [0; 64];
    let tag = Hmac::<A>::authenticate(&key, b"message", &mut output[..A::TAG_BYTES])?;
    assert_eq!(tag.bit_len(), A::TAG_BITS);
    let mut verifier = Hmac::<A>::new(&key)?;
    verifier.update(b"mes")?;
    verifier.update(b"sage")?;
    assert_eq!(verifier.verify(tag.as_bytes()), Ok(()));
    let mut forged = output;
    forged[0] ^= 1;
    let mut verifier = Hmac::<A>::new(&key)?;
    verifier.update(b"message")?;
    assert_eq!(verifier.verify(&forged[..A::TAG_BYTES]), Err(Error::Mismatch));
    let mut verifier = Hmac::<A>::new(&key)?;
    verifier.update(b"message")?;
    assert_eq!(verifier.verify(&output[..A::TAG_BYTES - 1]), Err(Error::TagLength));

    let mut truncated = [0; 16];
    let mut state = Hmac::<A>::with_tag_length(&key, 16)?;
    state.update(b"message")?;
    let tag = state.finalize_tag(&mut truncated)?;
    assert_eq!(tag.as_bytes(), &output[..16]);
    let mut verifier = Hmac::<A>::with_tag_length(&key, 16)?;
    verifier.update(b"mes")?;
    verifier.update(b"sage")?;
    assert_eq!(verifier.verify(tag.as_bytes()), Ok(()));
    truncated[0] ^= 1;
    let mut verifier = Hmac::<A>::with_tag_length(&key, 16)?;
    verifier.update(b"message")?;
    assert_eq!(verifier.verify(&truncated), Err(Error::Mismatch));

    let mut cleared = [0xa5; 64];
    let mut state = Hmac::<A>::new(&key)?;
    state.update(b"message")?;
    let secret = state.finalize_secret(&mut cleared[..A::TAG_BYTES])?;
    assert_eq!(secret.expose(), &output[..A::TAG_BYTES]);
    drop(secret);
    assert!(cleared[..A::TAG_BYTES].iter().all(|byte| *byte == 0));
    assert!(cleared[A::TAG_BYTES..].iter().all(|byte| *byte == 0xa5));
    Ok(())
}

#[test]
fn all_named_and_general_identities() -> Result<(), Error> {
    identity::<Sha224>()?; identity::<Sha256>()?;
    identity::<Sha384>()?; identity::<Sha512>()?;
    identity::<Sha512_224>()?; identity::<Sha512_256>()?;
    identity::<Sha3_224>()?; identity::<Sha3_256>()?;
    identity::<Sha3_384>()?; identity::<Sha3_512>()?;
    identity::<Sha512T<129>>()?; identity::<Sha512T<511>>()?;
    Ok(())
}

#[test]
fn exact_policy_and_output_failure() -> Result<(), Error> {
    assert!(matches!(Hmac::<Sha256>::with_tag_length(b"key", 15), Err(Error::TagLength)));
    assert!(matches!(Hmac::<Sha512T<127>>::new(b"key"), Err(Error::AlgorithmParameter)));
    assert!(matches!(Hmac::<Sha512T<129>>::with_tag_length(b"key", 17), Err(Error::TagLength)));
    let mut public = [0xa5; 31];
    assert!(Hmac::<Sha256>::new(b"key")?.finalize_tag(&mut public).is_err());
    assert_eq!(public, [0xa5; 31]);
    let mut secret = [0xa5; 31];
    assert!(Hmac::<Sha256>::new(b"key")?.finalize_secret(&mut secret).is_err());
    assert_eq!(secret, [0; 31]);
    let mut output = [0; 17];
    let tag = Hmac::<Sha512T<129>>::new(b"key")?.finalize_tag(&mut output)?;
    assert_eq!(tag.bit_len(), 129);
    assert_eq!(tag.as_bytes()[16] & 127, 0);
    Ok(())
}

#[test]
fn final_bit_order_is_preserved() -> Result<(), Error> {
    let mut output = [0; 32];
    let tag = Hmac::<Sha256>::new(b"key")?
        .finalize_bits_tag(Sha2BitString::new(&[0xa0], 3).unwrap(), &mut output)?;
    assert_eq!(Hmac::<Sha256>::new(b"key")?
        .verify_bits(Sha2BitString::new(&[0xa0], 3).unwrap(), tag.as_bytes()), Ok(()));
    let tag = Hmac::<Sha3_256>::new(b"key")?
        .finalize_bits_tag(Fips202BitString::new(&[5], 3).unwrap(), &mut output)?;
    assert_eq!(Hmac::<Sha3_256>::new(b"key")?
        .verify_bits(Fips202BitString::new(&[5], 3).unwrap(), tag.as_bytes()), Ok(()));
    Ok(())
}
