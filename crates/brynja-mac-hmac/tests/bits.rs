//! Exact bit lengths, public/secret ownership and finalization lifecycle.
#[macro_use]
mod support;
mod bit_support;
use bit_support::BitCase;
use brynja_mac_hmac::*;

fn exercise<A: BitCase>() {
    for key in [
        vec![],
        vec![0x42; A::BLOCK_BYTES],
        vec![0x5a; require_some!(A::BLOCK_BYTES.checked_add(1))],
    ] {
        for length in [
            0,
            1,
            55,
            56,
            111,
            112,
            require_some!(A::BLOCK_BYTES.checked_sub(1)),
            A::BLOCK_BYTES,
        ] {
            let bytes = vec![0x69; length];
            let mut full = vec![0; A::TAG_BYTES];
            let _ = require_ok!(Hmac::<A>::authenticate(&key, &bytes, &mut full));
            let mut aligned = vec![0; A::TAG_BYTES];
            let input = require_some!(A::input(&bytes, if length == 0 { 0 } else { 8 }));
            let _ = require_ok!(Hmac::<A>::authenticate_bits(&key, input, &mut aligned));
            assert_eq!(full, aligned);
            for valid in 1..=7 {
                let unused = require_some!(8_u8.checked_sub(valid));
                let tail = if A::LOW_BITS {
                    0xa5 >> unused
                } else {
                    0xa5 & (0xff << unused)
                };
                let mut message = bytes.clone();
                message.push(tail);
                let input = require_some!(A::input(&message, valid));
                let mut expected = vec![0; A::TAG_BYTES];
                let _ = require_ok!(Hmac::<A>::authenticate_bits(&key, input, &mut expected));
                let mut stream = require_ok!(Hmac::<A>::new(&key));
                require_ok!(stream.update(&bytes));
                require_ok!(stream.update(&[]));
                let last = [tail];
                let final_bits = require_some!(A::input(&last, valid));
                let mut output = vec![0xa5; A::TAG_BYTES];
                {
                    let secret = require_ok!(stream.finalize_bits_secret(final_bits, &mut output));
                    assert_eq!(secret.expose(), expected);
                }
                assert!(output.iter().all(|byte| *byte == 0));
                let verify = require_ok!(Hmac::<A>::with_tag_length(&key, 16));
                assert_eq!(
                    verify.verify_bits(input, require_some!(expected.get(..16))),
                    Ok(())
                );
                let last = require_some!(expected.last_mut());
                *last ^= 1;
                assert_eq!(
                    require_ok!(Hmac::<A>::new(&key)).verify_bits(input, &expected),
                    Err(Error::Mismatch)
                );
            }
        }
    }
    for length in [
        0,
        1,
        require_some!(A::TAG_BYTES.checked_sub(1)),
        require_some!(A::TAG_BYTES.checked_add(1)),
    ] {
        let input = require_some!(A::input(&[], 0));
        let mut output = vec![0xa5; length];
        assert!(matches!(
            require_ok!(Hmac::<A>::new(b"key")).finalize_bits_tag(input, &mut output),
            Err(Error::TagLength)
        ));
        assert!(output.iter().all(|byte| *byte == 0xa5));
        assert!(matches!(
            require_ok!(Hmac::<A>::new(b"key")).finalize_bits_secret(input, &mut output),
            Err(Error::TagLength)
        ));
        assert!(output.iter().all(|byte| *byte == 0));
        assert!(matches!(
            require_ok!(Hmac::<A>::new(b"key")).verify_bits(input, &output),
            Err(Error::TagLength)
        ));
    }
}

macro_rules! cases {
    ($($name:ident: $algorithm:ty),*) => {$(
        #[test] fn $name() { exercise::<$algorithm>(); }
    )*};
}
cases!(sha224: Sha224, sha256: Sha256, sha384: Sha384, sha512: Sha512,
       sha512_224: Sha512_224, sha512_256: Sha512_256, sha3_224: Sha3_224,
       sha3_256: Sha3_256, sha3_384: Sha3_384, sha3_512: Sha3_512);

fn known<A: BitCase>(hex: &str) {
    let expected = require_some!(support::decode(hex));
    let bytes = [if A::LOW_BITS { 1 } else { 0x80 }];
    let input = require_some!(A::input(&bytes, 1));
    let mut actual = vec![0; A::TAG_BYTES];
    let _ = require_ok!(Hmac::<A>::authenticate_bits(b"key", input, &mut actual));
    assert_eq!(actual, expected);
}

#[test]
fn known_bit_answers() {
    // One-bit message "1", byte key "key": separate Python SHA-2/Keccak models
    // via check-hmac-bit-differential.py. Author-derived, not official vectors.
    known::<Sha224>("816e24b14fe9e571de4d5bcbe9fa6b5617918c6ca1d075e705e79cd1");
    known::<Sha256>("d495bb3e5c0e957f9f15db0cf2b5f5364f4657e9401ddc36a8e77769e092f715");
    known::<Sha384>(
        "cb39f86fe92486d5b4a51755314e2472d11a8268c64a4d051e35b75a063b4719f1d6a8c9dac09ab39a75ca9fb977010f",
    );
    known::<Sha512>(
        "d30a3a1f5ee18b434260df11b8a0a89d9a6d8cd486585f9af0333af17932481ec68cac9e30968f307e4c978b0f81f30754935dfe0f92ecace25aa3add0bc6e16",
    );
    known::<Sha512_224>("6bccf84f14e23e4bde2ac61484996ee7e45b571f4025ba4a432d0d6a");
    known::<Sha512_256>("f10941439326641586158d094c9fb68f92a03b116131cb08eace84da60c334dd");
    known::<Sha3_224>("059b8b364fc9d39bc4e7ac8253b6c4c24dfdfaa5b843b2a5399ea523");
    known::<Sha3_256>("695614e6474577e0039c0b92e511d20ef083b12d1e330808da3746b75994f703");
    known::<Sha3_384>(
        "5957c8d5e854fb465e7df0ad4ad34c64faa5729412c059919947e8b8678efbae041feba8a83ff5d511065df05a273e50",
    );
    known::<Sha3_512>(
        "1f51c9924b8e39c76bcf4e333e6b1eb78b711c322356c5509b0466cc39b68e57d3480e7d3fd3d03fc3789e91400fd47d76968dd4b0ad7b3ea06a130f79e2e695",
    );
}

#[test]
fn canonicality_and_unwind() {
    assert_eq!(support::decode("a0"), Some(vec![0xa0]));
    for valid in [0, 9, u8::MAX] {
        assert!(Sha2BitString::new(&[0], valid).is_err());
        assert!(Fips202BitString::new(&[0], valid).is_err());
    }
    for valid in 1..=7 {
        assert!(Sha2BitString::new(&[1], valid).is_err());
        assert!(Fips202BitString::new(&[0x80], valid).is_err());
        assert!(Sha2BitString::new(&[], valid).is_err());
        assert!(Fips202BitString::new(&[], valid).is_err());
    }
    let mut output = [0xa5; 32];
    let input = require_ok!(Fips202BitString::new(&[5], 3));
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mac = require_ok!(Hmac::<Sha3_256>::new(b"key"));
        let secret = require_ok!(mac.finalize_bits_secret(input, &mut output));
        assert!(secret.expose().is_empty(), "synthetic consumer unwind");
    }));
    assert!(caught.is_err());
    assert_eq!(output, [0; 32]);
}
