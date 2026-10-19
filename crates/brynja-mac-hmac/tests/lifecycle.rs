//! Output, tag-policy and affine-owner lifecycle regressions.
#[macro_use]
mod support;

use brynja_mac_hmac::*;

fn exercise<A: Algorithm>() {
    for key_bytes in [
        0,
        1,
        require_some!(A::BLOCK_BYTES.checked_sub(1)),
        A::BLOCK_BYTES,
        require_some!(A::BLOCK_BYTES.checked_add(1)),
        1024,
    ] {
        let key = vec![0xa5; key_bytes];
        for tag_bytes in 16..=A::TAG_BYTES {
            let mut expected = vec![0; tag_bytes];
            let mut mac = require_ok!(Hmac::<A>::with_tag_length(&key, tag_bytes));
            require_ok!(mac.update(b"message"));
            let _tag = require_ok!(mac.finalize_tag(&mut expected));

            let mut verifier = require_ok!(Hmac::<A>::with_tag_length(&key, tag_bytes));
            require_ok!(verifier.update(b"message"));
            assert!(require_ok!(verifier.verify(&expected)).expose_public());
            for position in [
                0,
                require_some!(tag_bytes.checked_div(2)),
                require_some!(tag_bytes.checked_sub(1)),
            ] {
                let mut bad = expected.clone();
                *require_some!(bad.get_mut(position)) ^= 1;
                let mut verifier = require_ok!(Hmac::<A>::with_tag_length(&key, tag_bytes));
                require_ok!(verifier.update(b"message"));
                assert!(!require_ok!(verifier.verify(&bad)).expose_public());
            }

            let mut secret_bytes = vec![0xff; tag_bytes];
            let mut mac = require_ok!(Hmac::<A>::with_tag_length(&key, tag_bytes));
            require_ok!(mac.update(b"message"));
            {
                let secret = require_ok!(mac.finalize_secret(&mut secret_bytes));
                assert_eq!(secret.expose(), expected);
            }
            assert_eq!(secret_bytes, vec![0; tag_bytes]);
        }
    }
    for size in [0, 1, 15, require_some!(A::TAG_BYTES.checked_add(1)), 200] {
        assert!(matches!(
            Hmac::<A>::with_tag_length(b"key", size),
            Err(Error::TagLength)
        ));
    }
    for size in [
        0,
        1,
        require_some!(A::TAG_BYTES.checked_sub(1)),
        require_some!(A::TAG_BYTES.checked_add(1)),
    ] {
        let mut output = vec![0xa5; size];
        assert!(matches!(
            require_ok!(Hmac::<A>::new(b"key")).finalize_tag(&mut output),
            Err(Error::TagLength)
        ));
        assert_eq!(output, vec![0xa5; size]);
        assert!(matches!(
            require_ok!(Hmac::<A>::new(b"key")).finalize_secret(&mut output),
            Err(Error::TagLength)
        ));
        assert_eq!(output, vec![0; size]);
        assert!(matches!(
            require_ok!(Hmac::<A>::new(b"key")).verify(&output),
            Err(Error::TagLength)
        ));
    }
}

macro_rules! cases {
    ($($name:ident: $algorithm:ty),* $(,)?) => {$(
        #[test]
        fn $name() { exercise::<$algorithm>(); }
    )*};
}

cases!(sha224: Sha224, sha256: Sha256, sha384: Sha384, sha512: Sha512,
       sha512_224: Sha512_224, sha512_256: Sha512_256, sha3_224: Sha3_224,
       sha3_256: Sha3_256, sha3_384: Sha3_384, sha3_512: Sha3_512);

#[test]
fn secret_output_clears_on_unwind() {
    assert_eq!(support::decode("00"), Some(vec![0]));
    let mut bytes = [0xa5; 32];
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mac = require_ok!(Hmac::<Sha256>::new(b"key"));
        let secret = require_ok!(mac.finalize_secret(&mut bytes));
        assert!(secret.expose().is_empty(), "synthetic consumer unwind");
    }));
    assert!(result.is_err());
    assert_eq!(bytes, [0; 32]);
}
