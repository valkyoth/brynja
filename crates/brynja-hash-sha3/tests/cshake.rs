//! Complete cSHAKE128 and cSHAKE256 acceptance tests.

use brynja_hash_sha3::{
    Cshake128, Cshake256, Fips202BitString, Fips202Output, HardenedCshake128,
    Sha3PublicDeclassification, cshake128, cshake128_bits, cshake256, shake128, shake256,
};

const SAMPLE_128_SHORT: [u8; 32] = [
    0xc1, 0xc3, 0x69, 0x25, 0xb6, 0x40, 0x9a, 0x04, 0xf1, 0xb5, 0x04, 0xfc, 0xbc, 0xa9, 0xd8, 0x2b,
    0x40, 0x17, 0x27, 0x7c, 0xb5, 0xed, 0x2b, 0x20, 0x65, 0xfc, 0x1d, 0x38, 0x14, 0xd5, 0xaa, 0xf5,
];
const SAMPLE_128_LONG: [u8; 32] = [
    0xc5, 0x22, 0x1d, 0x50, 0xe4, 0xf8, 0x22, 0xd9, 0x6a, 0x2e, 0x88, 0x81, 0xa9, 0x61, 0x42, 0x0f,
    0x29, 0x4b, 0x7b, 0x24, 0xfe, 0x3d, 0x20, 0x94, 0xba, 0xed, 0x2c, 0x65, 0x24, 0xcc, 0x16, 0x6b,
];
const SAMPLE_256_SHORT: [u8; 64] = [
    0xd0, 0x08, 0x82, 0x8e, 0x2b, 0x80, 0xac, 0x9d, 0x22, 0x18, 0xff, 0xee, 0x1d, 0x07, 0x0c, 0x48,
    0xb8, 0xe4, 0xc8, 0x7b, 0xff, 0x32, 0xc9, 0x69, 0x9d, 0x5b, 0x68, 0x96, 0xee, 0xe0, 0xed, 0xd1,
    0x64, 0x02, 0x0e, 0x2b, 0xe0, 0x56, 0x08, 0x58, 0xd9, 0xc0, 0x0c, 0x03, 0x7e, 0x34, 0xa9, 0x69,
    0x37, 0xc5, 0x61, 0xa7, 0x4c, 0x41, 0x2b, 0xb4, 0xc7, 0x46, 0x46, 0x95, 0x27, 0x28, 0x1c, 0x8c,
];
const SAMPLE_256_LONG: [u8; 64] = [
    0x07, 0xdc, 0x27, 0xb1, 0x1e, 0x51, 0xfb, 0xac, 0x75, 0xbc, 0x7b, 0x3c, 0x1d, 0x98, 0x3e, 0x8b,
    0x4b, 0x85, 0xfb, 0x1d, 0xef, 0xaf, 0x21, 0x89, 0x12, 0xac, 0x86, 0x43, 0x02, 0x73, 0x09, 0x17,
    0x27, 0xf4, 0x2b, 0x17, 0xed, 0x1d, 0xf6, 0x3e, 0x8e, 0xc1, 0x18, 0xf0, 0x4b, 0x23, 0x63, 0x3c,
    0x1d, 0xfb, 0x15, 0x74, 0xc8, 0xfb, 0x55, 0xcb, 0x45, 0xda, 0x8e, 0x25, 0xaf, 0xb0, 0x92, 0xbb,
];

#[test]
fn every_official_nist_cshake_example_matches() {
    let short = [0_u8, 1, 2, 3];
    let long: [u8; 200] = core::array::from_fn(|index| u8::try_from(index).unwrap_or_default());
    let customization = b"Email Signature";
    let mut output128 = [0_u8; 32];
    let mut output256 = [0_u8; 64];

    assert_eq!(
        cshake128(&short, b"", customization, &mut output128),
        Ok(())
    );
    assert_eq!(output128, SAMPLE_128_SHORT);
    assert_eq!(cshake128(&long, b"", customization, &mut output128), Ok(()));
    assert_eq!(output128, SAMPLE_128_LONG);
    assert_eq!(
        cshake256(&short, b"", customization, &mut output256),
        Ok(())
    );
    assert_eq!(output256, SAMPLE_256_SHORT);
    assert_eq!(cshake256(&long, b"", customization, &mut output256), Ok(()));
    assert_eq!(output256, SAMPLE_256_LONG);
}

#[test]
fn empty_name_and_customization_are_exactly_shake() {
    let message = b"cSHAKE empty-domain equivalence";
    let mut c128 = [0_u8; 257];
    let mut s128 = [0_u8; 257];
    let mut c256 = [0_u8; 273];
    let mut s256 = [0_u8; 273];
    assert_eq!(cshake128(message, b"", b"", &mut c128), Ok(()));
    assert_eq!(shake128(message, &mut s128), Ok(()));
    assert_eq!(c128, s128);
    assert_eq!(cshake256(message, b"", b"", &mut c256), Ok(()));
    assert_eq!(shake256(message, &mut s256), Ok(()));
    assert_eq!(c256, s256);
}

#[test]
fn streaming_and_partitioned_output_match_one_shot() {
    let mut expected = [0_u8; 400];
    assert_eq!(
        cshake128(b"abcdef", b"Function", b"Context", &mut expected),
        Ok(())
    );

    let state = Cshake128::new(b"Function", b"Context");
    assert!(state.is_ok());
    if let Ok(mut state) = state {
        assert_eq!(state.message_bytes(), 0);
        assert_eq!(state.update(b"ab"), Ok(()));
        assert_eq!(state.update(b"cdef"), Ok(()));
        assert_eq!(state.message_bytes(), 6);
        let mut reader = state.finalize_xof();
        let mut actual = [0_u8; 400];
        let (first, rest) = actual.split_at_mut(31);
        let (second, third) = rest.split_at_mut(168);
        assert_eq!(reader.squeeze(first), Ok(()));
        assert_eq!(reader.squeeze(second), Ok(()));
        assert_eq!(reader.squeeze(third), Ok(()));
        assert_eq!(reader.output_bytes(), 400);
        assert_eq!(actual, expected);
    }
}

#[test]
fn arbitrary_bit_parameters_message_and_output_are_stable() {
    let n = Fips202BitString::new(&[0x05], 3);
    let s = Fips202BitString::new(&[0x02], 2);
    let message = Fips202BitString::new(&[0xa5, 0x03], 2);
    assert!(n.is_ok() && s.is_ok() && message.is_ok());
    if let (Ok(n), Ok(s), Ok(message)) = (n, s, message) {
        let mut first = [0_u8; 34];
        let mut second = [0_u8; 34];
        let first_output = Fips202Output::new(&mut first, 5);
        assert!(first_output.is_ok());
        if let Ok(first_output) = first_output {
            assert_eq!(cshake128_bits(message, n, s, first_output), Ok(()));
        }
        let state = Cshake128::new_bits(n, s);
        assert!(state.is_ok());
        if let Ok(state) = state {
            let reader = state.finalize_bits_xof(message);
            assert!(reader.is_ok());
            if let Ok(reader) = reader {
                let second_output = Fips202Output::new(&mut second, 5);
                assert!(second_output.is_ok());
                if let Ok(second_output) = second_output {
                    assert_eq!(reader.squeeze_final_bits(second_output), Ok(()));
                }
            }
        }
        assert_eq!(first, second);
        assert_eq!(first.last().copied().unwrap_or_default() & 0xe0, 0);
    }
}

#[test]
fn hardened_state_matches_and_clears_secret_output() {
    let state = HardenedCshake128::new(b"", b"Email Signature");
    assert!(state.is_ok());
    let mut secret_bytes = [0_u8; 32];
    if let Ok(mut state) = state {
        assert_eq!(state.message_bytes(), 0);
        assert_eq!(state.update(&[0, 1, 2, 3]), Ok(()));
        assert_eq!(state.message_bytes(), 4);
        let secret = state.finalize_secret(&mut secret_bytes);
        assert!(secret.is_ok());
        if let Ok(secret) = secret {
            assert_eq!(secret.expose(), SAMPLE_128_SHORT);
        }
    }
    assert_eq!(secret_bytes, [0; 32]);

    let state = HardenedCshake128::new(b"", b"Email Signature");
    let mut public = [0_u8; 32];
    if let Ok(mut state) = state {
        assert_eq!(state.update(&[0, 1, 2, 3]), Ok(()));
        assert_eq!(
            state.finalize_public(&mut public, Sha3PublicDeclassification::acknowledge()),
            Ok(())
        );
    }
    assert_eq!(public, SAMPLE_128_SHORT);
}

#[test]
fn strengths_and_domains_are_distinct() {
    let mut a = [0_u8; 32];
    let mut b = [0_u8; 32];
    let mut c = [0_u8; 32];
    assert_eq!(cshake128(b"message", b"", b"A", &mut a), Ok(()));
    assert_eq!(cshake128(b"message", b"", b"B", &mut b), Ok(()));
    assert_eq!(cshake256(b"message", b"", b"A", &mut c), Ok(()));
    assert_ne!(a, b);
    assert_ne!(a, c);

    let state = Cshake256::new(b"N", b"S");
    assert!(state.is_ok());
}
