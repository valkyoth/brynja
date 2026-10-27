//! Key-independent policy agrees with real constructors, including error precedence.
use brynja_mac_hmac::{self as mac, Algorithm, Error, Hmac, validate_tag_policy};

fn check<A: Algorithm>(valid: bool) {
    let full = if valid {
        Ok(A::TAG_BITS)
    } else {
        Err(Error::AlgorithmParameter)
    };
    assert_eq!(validate_tag_policy::<A>(None), full);
    assert_eq!(
        Hmac::<A>::new(b"public test key").map(|_| ()),
        full.map(|_| ())
    );
    for bytes in (0..=65).chain([usize::MAX / 8, usize::MAX / 8 + 1, usize::MAX]) {
        // An independent mathematical predicate, not the implementation helper.
        let expected = if !valid {
            Err(Error::AlgorithmParameter)
        } else if (16..=A::TAG_BITS / 8).contains(&bytes) {
            Ok(bytes.saturating_mul(8))
        } else {
            Err(Error::TagLength)
        };
        assert_eq!(validate_tag_policy::<A>(Some(bytes)), expected);
        assert_eq!(
            Hmac::<A>::with_tag_length(b"public test key", bytes).map(|_| ()),
            expected.map(|_| ())
        );
    }
}

#[test]
fn every_named_algorithm_and_tag_width() {
    check::<mac::Sha224>(true);
    check::<mac::Sha256>(true);
    check::<mac::Sha384>(true);
    check::<mac::Sha512>(true);
    check::<mac::Sha512_224>(true);
    check::<mac::Sha512_256>(true);
    check::<mac::Sha3_224>(true);
    check::<mac::Sha3_256>(true);
    check::<mac::Sha3_384>(true);
    check::<mac::Sha3_512>(true);
}

#[test]
fn fractional_full_tags_are_not_byte_prefixes() {
    check::<mac::Sha512T<128>>(true);
    check::<mac::Sha512T<129>>(true);
    check::<mac::Sha512T<135>>(true);
    check::<mac::Sha512T<255>>(true);
    check::<mac::Sha512T<511>>(true);
}

#[test]
fn invalid_algorithms_precede_width_and_overflow_errors() {
    check::<mac::Sha512T<0>>(false);
    check::<mac::Sha512T<127>>(false);
    check::<mac::Sha512T<384>>(false);
    check::<mac::Sha512T<512>>(false);
    check::<mac::Sha512T<65535>>(false);
}
