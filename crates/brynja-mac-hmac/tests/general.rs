//! General SHA-512/t HMAC policy, exact-bit composition and output lifecycle.
#[macro_use]
mod support;
use brynja_mac_hmac::*;

fn exercise<const T: u16>() {
    type Input<'a> = Sha2BitString<'a>;
    let width = Sha512T::<T>::TAG_BYTES;
    for key in [vec![], vec![0x42; 128], vec![0x5a; 129], vec![0x69; 257]] {
        for size in [0, 1, 111, 112, 127, 128, 129, 255] {
            let message = vec![0xa5; size];
            let mut full = vec![0; width];
            {
                let tag = require_ok!(Hmac::<Sha512T<T>>::authenticate(&key, &message, &mut full));
                assert_eq!(tag.bit_len(), usize::from(T));
            }
            let mut stream = require_ok!(Hmac::<Sha512T<T>>::new(&key));
            for chunk in message.chunks(17) {
                require_ok!(stream.update(chunk));
            }
            let mut secret_bytes = vec![0xa5; width];
            {
                let secret = require_ok!(stream.finalize_secret(&mut secret_bytes));
                assert_eq!(secret.bit_len(), usize::from(T));
                assert_eq!(secret.expose(), full);
            }
            assert!(secret_bytes.iter().all(|byte| *byte == 0));
            let mut verifier = require_ok!(Hmac::<Sha512T<T>>::new(&key));
            require_ok!(verifier.update(&message));
            assert_eq!(verifier.verify(&full), Ok(()));
            let mut short = [0; 16];
            let mut mac = require_ok!(Hmac::<Sha512T<T>>::with_tag_length(&key, 16));
            require_ok!(mac.update(&message));
            let tag = require_ok!(mac.finalize_tag(&mut short));
            assert_eq!(tag.bit_len(), 128);
            assert_eq!(tag.as_bytes(), require_some!(full.get(..16)));
            for valid in 1..=7 {
                let mut tail = message.clone();
                tail.push(0x80);
                let input = require_ok!(Input::new(&tail, valid));
                let _ = require_ok!(Hmac::<Sha512T<T>>::authenticate_bits(
                    &key, input, &mut full
                ));
                let mut stream = require_ok!(Hmac::<Sha512T<T>>::new(&key));
                require_ok!(stream.update(&message));
                let last = require_ok!(Input::new(&[0x80], valid));
                let secret = require_ok!(stream.finalize_bits_secret(last, &mut secret_bytes));
                assert_eq!(secret.expose(), full);
                drop(secret);
                assert!(secret_bytes.iter().all(|byte| *byte == 0));
                let verifier = require_ok!(Hmac::<Sha512T<T>>::new(&key));
                assert_eq!(verifier.verify_bits(input, &full), Ok(()));
            }
        }
    }
    for size in [
        0,
        1,
        require_some!(width.checked_sub(1)),
        require_some!(width.checked_add(1)),
    ] {
        let mut output = vec![0xa5; size];
        assert!(matches!(
            require_ok!(Hmac::<Sha512T<T>>::new(b"key")).finalize_tag(&mut output),
            Err(Error::TagLength)
        ));
        assert!(output.iter().all(|byte| *byte == 0xa5));
        assert!(matches!(
            require_ok!(Hmac::<Sha512T<T>>::new(b"key")).finalize_secret(&mut output),
            Err(Error::TagLength)
        ));
        assert!(output.iter().all(|byte| *byte == 0));
    }
}

#[test]
fn boundary_lifecycle() {
    exercise::<128>();
    exercise::<129>();
    exercise::<135>();
    exercise::<136>();
    exercise::<224>();
    exercise::<255>();
    exercise::<256>();
    exercise::<383>();
    exercise::<385>();
    exercise::<511>();
}

fn invalid<const T: u16>() {
    for key in [vec![], vec![0x42; 129]] {
        assert!(matches!(
            Hmac::<Sha512T<T>>::new(&key),
            Err(Error::AlgorithmParameter)
        ));
        assert!(matches!(
            Hmac::<Sha512T<T>>::with_tag_length(&key, 16),
            Err(Error::AlgorithmParameter | Error::TagLength)
        ));
        let mut output = [0xa5; 64];
        assert!(Hmac::<Sha512T<T>>::authenticate(&key, b"message", &mut output).is_err());
        assert_eq!(output, [0xa5; 64]);
    }
}

#[test]
fn parameter_and_truncation_policy() {
    invalid::<0>();
    invalid::<1>();
    invalid::<127>();
    invalid::<384>();
    invalid::<512>();
    invalid::<65535>();
    assert!(matches!(
        Hmac::<Sha512T<129>>::with_tag_length(b"key", 17),
        Err(Error::TagLength)
    ));
    for width in [0, 1, 15, 65, usize::MAX] {
        assert!(matches!(
            Hmac::<Sha512T<511>>::with_tag_length(b"key", width),
            Err(Error::TagLength)
        ));
    }
}

#[test]
fn named_identity_controls() {
    for key in [vec![], vec![0x42; 128], vec![0x5a; 129]] {
        let mut named = [0; 28];
        let mut general = [0; 28];
        let _ = require_ok!(Hmac::<Sha512_224>::authenticate(
            &key, b"message", &mut named
        ));
        let _ = require_ok!(Hmac::<Sha512T<224>>::authenticate(
            &key,
            b"message",
            &mut general
        ));
        assert_eq!(named, general);
        let mut named = [0; 32];
        let mut general = [0; 32];
        let input = require_ok!(Sha2BitString::new(&[0xa0], 3));
        let _ = require_ok!(Hmac::<Sha512_256>::authenticate_bits(
            &key, input, &mut named
        ));
        let _ = require_ok!(Hmac::<Sha512T<256>>::authenticate_bits(
            &key,
            input,
            &mut general
        ));
        assert_eq!(named, general);
    }
}

fn known<const T: u16>(hex: &str) {
    let expected = require_some!(support::decode(hex));
    let mut output = vec![0; expected.len()];
    let tag = require_ok!(Hmac::<Sha512T<T>>::authenticate(
        b"key",
        b"abc",
        &mut output
    ));
    assert_eq!(tag.as_bytes(), expected);
}

#[test]
fn exact_inner_bit_answers() {
    // Author-generated by the separate Python general SHA-512/t model,
    // not official vectors or evidence of independent review.
    known::<129>("f46567c38cfca2b6844694cbdcb991d200");
    known::<255>("b392b349fb3497a14dca5e94fda81d369cd68fbf4883d2599dd3611404bf0cd0");
    known::<511>(
        "ff91f8e7a4df26de3640b914f50da740052c956808b21db84938b6934955e4437176d87baa1ad657922ba87b72f23fd3f55c063f8456428a91963df0715cfc80",
    );
}

#[test]
fn fractional_profile_never_rounds_inner_digest_to_bytes() {
    // A construction regression, not an independent oracle or official vector.
    // Both public hash compositions below use only this synthetic public key.
    use brynja_hash_sha2::{Sha512T as Hash, Sha512TBits};
    let parameter = require_ok!(Sha512TBits::new(129));
    let mut ipad = [0x36; 128];
    let mut opad = [0x5c; 128];
    for ((i, o), k) in ipad.iter_mut().zip(opad.iter_mut()).zip(b"key") {
        *i ^= k;
        *o ^= k;
    }
    let mut inner = Hash::new(parameter);
    require_ok!(inner.update(&ipad));
    require_ok!(inner.update(b"abc"));
    let digest = require_ok!(inner.finalize());
    let mut exact = Hash::new(parameter);
    require_ok!(exact.update(&opad));
    let expected =
        require_ok!(exact.finalize_bits(require_ok!(Sha2BitString::new(digest.as_bytes(), 1))));
    let mut rounded = Hash::new(parameter);
    require_ok!(rounded.update(&opad));
    require_ok!(rounded.update(digest.as_bytes()));
    let wrong = require_ok!(rounded.finalize());
    let mut actual = [0; 17];
    let tag = require_ok!(Hmac::<Sha512T<129>>::authenticate(
        b"key",
        b"abc",
        &mut actual
    ));
    assert_eq!(tag.as_bytes(), expected.as_bytes());
    assert_ne!(tag.as_bytes(), wrong.as_bytes());
}

#[test]
fn canonical_verification_and_unwind() {
    let mut output = [0; 17];
    let _ = require_ok!(Hmac::<Sha512T<129>>::authenticate(b"key", b"", &mut output));
    assert_eq!(output[16] & 0x7f, 0);
    for mask in [1, 2, 4, 8, 16, 32, 64, 128] {
        let mut changed = output;
        changed[16] ^= mask;
        assert_eq!(
            require_ok!(Hmac::<Sha512T<129>>::new(b"key")).verify(&changed),
            Err(Error::Mismatch)
        );
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mac = require_ok!(Hmac::<Sha512T<129>>::new(b"key"));
        let secret = require_ok!(mac.finalize_secret(&mut output));
        assert!(secret.expose().is_empty(), "synthetic consumer unwind");
    }));
    assert!(result.is_err());
    assert_eq!(output, [0; 17]);
}
