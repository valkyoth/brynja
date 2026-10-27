fn legacy_identity<A: legacy::Algorithm>() {
    let key = [0x52; 257];
    let mut output = [0; 20];
    let tag = legacy::Hmac::<A>::authenticate(
        legacy::LegacyUse::acknowledge(),
        &key,
        b"message",
        &mut output[..A::TAG_BYTES],
    )
    .unwrap();
    let mut state = legacy::Hmac::<A>::new(legacy::LegacyUse::acknowledge(), &key).unwrap();
    state.update(b"mes").unwrap();
    state.update(b"sage").unwrap();
    assert_eq!(state.verify(tag.as_bytes()), Ok(()));
    output[0] ^= 1;
    let mut state = legacy::Hmac::<A>::new(legacy::LegacyUse::acknowledge(), &key).unwrap();
    state.update(b"message").unwrap();
    assert_eq!(
        state.verify(&output[..A::TAG_BYTES]),
        Err(legacy::VerificationError::Mismatch(()))
    );
    output[0] ^= 1;
    let mut state = legacy::Hmac::<A>::new(legacy::LegacyUse::acknowledge(), &key).unwrap();
    state.update(b"message").unwrap();
    assert_eq!(
        state.verify(&output[..A::TAG_BYTES - 1]),
        Err(legacy::VerificationError::Operation(
            legacy::Error::TagLength
        ))
    );
    let mut truncated = [0; 10];
    let mut state =
        legacy::Hmac::<A>::with_tag_length(legacy::LegacyUse::acknowledge(), &key, 10).unwrap();
    state.update(b"message").unwrap();
    assert_eq!(
        state.finalize_tag(&mut truncated).unwrap().as_bytes(),
        &output[..10]
    );
    let mut state =
        legacy::Hmac::<A>::with_tag_length(legacy::LegacyUse::acknowledge(), &key, 10).unwrap();
    state.update(b"message").unwrap();
    assert_eq!(state.verify(&truncated), Ok(()));
    truncated[0] ^= 1;
    let mut state =
        legacy::Hmac::<A>::with_tag_length(legacy::LegacyUse::acknowledge(), &key, 10).unwrap();
    state.update(b"message").unwrap();
    assert_eq!(
        state.verify(&truncated),
        Err(legacy::VerificationError::Mismatch(()))
    );
    let mut cleared = [0xa5; 24];
    let mut state = legacy::Hmac::<A>::new(legacy::LegacyUse::acknowledge(), &key).unwrap();
    state.update(b"message").unwrap();
    let secret = state.finalize_secret(&mut cleared[..A::TAG_BYTES]).unwrap();
    assert_eq!(secret.expose(), &output[..A::TAG_BYTES]);
    drop(secret);
    assert!(cleared[..A::TAG_BYTES].iter().all(|byte| *byte == 0));
    assert!(cleared[A::TAG_BYTES..].iter().all(|byte| *byte == 0xa5));
}

#[test]
fn explicitly_selected_legacy_streams() {
    legacy_identity::<legacy::Md5>();
    legacy_identity::<legacy::Sha1>();
}

#[test]
fn legacy_rfc2202_vectors() {
    let mut md5 = [0; 16];
    legacy::Hmac::<legacy::Md5>::authenticate(
        legacy::LegacyUse::acknowledge(),
        &[0x0b; 16],
        b"Hi There",
        &mut md5,
    )
    .unwrap();
    assert_eq!(
        md5,
        [
            0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c, 0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b,
            0xfc, 0x9d
        ]
    );
    let mut sha1 = [0; 20];
    legacy::Hmac::<legacy::Sha1>::authenticate(
        legacy::LegacyUse::acknowledge(),
        &[0x0b; 20],
        b"Hi There",
        &mut sha1,
    )
    .unwrap();
    assert_eq!(
        sha1,
        [
            0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37,
            0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00
        ]
    );
}

#[test]
fn legacy_minimum_cannot_relax_modern_policy() {
    assert!(
        legacy::Hmac::<legacy::Md5>::with_tag_length(legacy::LegacyUse::acknowledge(), b"key", 10)
            .is_ok()
    );
    assert!(matches!(
        Hmac::<Sha256>::with_tag_length(b"key", 10),
        Err(Error::TagLength)
    ));
    assert!(matches!(
        Hmac::<Sha512T<128>>::with_tag_length(b"key", 10),
        Err(Error::TagLength)
    ));
    assert!(matches!(
        legacy::Hmac::<legacy::Sha1>::with_tag_length(legacy::LegacyUse::acknowledge(), b"key", 9),
        Err(legacy::Error::TagLength)
    ));
}
