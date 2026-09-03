//! SP 800-185 encoding acceptance tests.

use brynja_hash_sha3::{
    Fips202BitString, Sp800185EncodingError, Sp800185Integer, bytepad, encode_string, left_encode,
    left_encode_u128, right_encode, right_encode_u128,
};

#[test]
fn integer_encodings_cover_boundaries_and_complete_domain() {
    assert_eq!(left_encode_u128(0).as_bytes(), &[1, 0]);
    assert_eq!(right_encode_u128(0).as_bytes(), &[0, 1]);
    assert_eq!(left_encode_u128(168).as_bytes(), &[1, 168]);
    assert_eq!(right_encode_u128(168).as_bytes(), &[168, 1]);
    assert_eq!(left_encode_u128(256).as_bytes(), &[2, 1, 0]);
    assert_eq!(right_encode_u128(256).as_bytes(), &[1, 0, 2]);

    let maximum = [0xff_u8; 255];
    let value = Sp800185Integer::from_be_bytes(&maximum);
    assert!(value.is_ok());
    if let Ok(value) = value {
        let left = left_encode(value);
        let right = right_encode(value);
        assert_eq!(left.as_bytes().len(), 256);
        assert_eq!(left.as_bytes().first(), Some(&255));
        assert_eq!(left.as_bytes().get(1..), Some(&maximum[..]));
        assert_eq!(right.as_bytes().get(..255), Some(&maximum[..]));
        assert_eq!(right.as_bytes().last(), Some(&255));
    }
}

#[test]
fn noncanonical_integers_are_rejected() {
    assert!(matches!(
        Sp800185Integer::from_be_bytes(&[]),
        Err(Sp800185EncodingError::EmptyInteger)
    ));
    assert!(matches!(
        Sp800185Integer::from_be_bytes(&[0, 1]),
        Err(Sp800185EncodingError::NonCanonicalInteger)
    ));
    assert!(matches!(
        Sp800185Integer::from_be_bytes(&[1; 256]),
        Err(Sp800185EncodingError::IntegerTooLarge)
    ));
}

#[test]
fn encode_string_preserves_exact_arbitrary_bits() {
    let empty = Fips202BitString::new(&[], 0);
    assert!(empty.is_ok());
    if let Ok(empty) = empty {
        let mut output = [0_u8; 2];
        let shape = encode_string(empty, &mut output);
        assert_eq!(output, [1, 0]);
        assert_eq!(shape.map(|value| value.bits()), Ok(16));
    }

    let partial = Fips202BitString::new(&[0x05], 3);
    assert!(partial.is_ok());
    if let Ok(partial) = partial {
        let mut output = [0_u8; 3];
        let shape = encode_string(partial, &mut output);
        assert_eq!(output, [1, 3, 0x05]);
        assert_eq!(shape.map(|value| value.bits()), Ok(19));
        assert_eq!(shape.map(|value| value.valid_bits_in_last_byte()), Ok(3));
    }
}

#[test]
fn bytepad_is_exact_and_transactional() {
    let input = Fips202BitString::new(b"Email Signature", 8);
    assert!(input.is_ok());
    if let Ok(input) = input {
        let mut encoded = [0_u8; 17];
        assert_eq!(
            encode_string(input, &mut encoded).map(|shape| shape.bits()),
            Ok(136)
        );
        let encoded = Fips202BitString::new(&encoded, 8);
        assert!(encoded.is_ok());
        if let Ok(encoded) = encoded {
            let mut padded = [0xa5_u8; 24];
            assert_eq!(bytepad(encoded, 8, &mut padded), Ok(24));
            assert_eq!(
                &padded[..19],
                &[
                    1, 8, 1, 120, 69, 109, 97, 105, 108, 32, 83, 105, 103, 110, 97, 116, 117, 114,
                    101
                ]
            );
            assert!(padded[19..].iter().all(|byte| *byte == 0));
        }
    }

    let empty = Fips202BitString::new(&[], 0);
    assert!(empty.is_ok());
    if let Ok(empty) = empty {
        let mut unchanged = [0x5a_u8; 8];
        assert_eq!(
            bytepad(empty, 0, &mut unchanged),
            Err(Sp800185EncodingError::InvalidWidth)
        );
        assert_eq!(unchanged, [0x5a; 8]);
        let mut wrong_length = [0x5a_u8; 7];
        assert_eq!(
            bytepad(empty, 8, &mut wrong_length),
            Err(Sp800185EncodingError::OutputLength)
        );
        assert_eq!(wrong_length, [0x5a; 7]);
    }
}
