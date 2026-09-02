//! FIPS 202 arbitrary-bit input and output acceptance.

use brynja_hash_sha3::{
    Fips202BitString, Fips202BitsError, Fips202Output, Sha3_256, Shake128, Shake256, sha3_224,
    sha3_224_bits, sha3_256, sha3_256_bits, sha3_384, sha3_384_bits, sha3_512, sha3_512_bits,
    shake128, shake128_bits, shake256, shake256_bits,
};

type TestResult = Result<(), &'static str>;
const NIST_VECTORS: &str = include_str!("vectors/nist-bit-selected.txt");

#[test]
fn curated_nist_cavp_vectors_cover_every_function_and_bit_residue() {
    let mut count = 0_usize;
    for line in NIST_VECTORS
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        assert!(check_vector(line));
        count = count.saturating_add(1);
    }
    assert_eq!(count, 76);
}

fn check_vector(line: &str) -> bool {
    let mut fields = line.split_whitespace();
    let algorithm = fields.next().unwrap_or_default();
    let Some(input_bits) = fields.next().and_then(parse_usize) else {
        return false;
    };
    let Some(output_bits) = fields.next().and_then(parse_usize) else {
        return false;
    };
    let Some(mut message) = fields.next().and_then(decode_hex) else {
        return false;
    };
    let Some(mut expected) = fields.next().and_then(decode_hex) else {
        return false;
    };
    if fields.next().is_some() {
        return false;
    }
    message.truncate(input_bits.saturating_add(7) / 8);
    expected.truncate(output_bits.saturating_add(7) / 8);
    let Some(input) = canonical(&message, input_bits) else {
        return false;
    };
    match algorithm {
        "sha3-224" => sha3_224_bits(input)
            .map(|value| value.as_bytes().as_slice() == expected.as_slice())
            .unwrap_or(false),
        "sha3-256" => sha3_256_bits(input)
            .map(|value| value.as_bytes().as_slice() == expected.as_slice())
            .unwrap_or(false),
        "sha3-384" => sha3_384_bits(input)
            .map(|value| value.as_bytes().as_slice() == expected.as_slice())
            .unwrap_or(false),
        "sha3-512" => sha3_512_bits(input)
            .map(|value| value.as_bytes().as_slice() == expected.as_slice())
            .unwrap_or(false),
        "shake128" => check_xof(input, output_bits, &expected, true),
        "shake256" => check_xof(input, output_bits, &expected, false),
        _ => false,
    }
}

fn check_xof(input: Fips202BitString<'_>, bits: usize, expected: &[u8], strength128: bool) -> bool {
    let mut output = vec![0_u8; bits.saturating_add(7) / 8];
    let valid = valid_bits(bits);
    let Ok(destination) = Fips202Output::new(&mut output, valid) else {
        return false;
    };
    let success = if strength128 {
        shake128_bits(input, destination).is_ok()
    } else {
        shake256_bits(input, destination).is_ok()
    };
    success && output == expected
}

fn canonical(bytes: &[u8], bits: usize) -> Option<Fips202BitString<'_>> {
    Fips202BitString::new(bytes, valid_bits(bits)).ok()
}

fn valid_bits(bits: usize) -> u8 {
    if bits == 0 {
        0
    } else {
        u8::try_from(bits.saturating_sub(1) % 8)
            .unwrap_or(7)
            .saturating_add(1)
    }
}

fn parse_usize(value: &str) -> Option<usize> {
    value.parse().ok()
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let [high, low] = pair else {
                return None;
            };
            Some(nibble_option(*high)?.wrapping_shl(4) | nibble_option(*low)?)
        })
        .collect()
}

fn nibble_option(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(value.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    }
}

#[test]
fn official_nist_five_bit_examples_match_all_six_identities() -> TestResult {
    let message = Fips202BitString::new(&[0x13], 5).map_err(|_| "NIST message")?;
    assert_eq!(
        sha3_224_bits(message).map_err(|_| "SHA3-224")?.as_bytes(),
        &hex::<28>("ffbad5da96bad71789330206dc6768ecaeb1b32dca6b3301489674ab")
    );
    assert_eq!(
        sha3_256_bits(message).map_err(|_| "SHA3-256")?.as_bytes(),
        &hex::<32>("7b0047cf5a456882363cbf0fb05322cf65f4b7059a46365e830132e3b5d957af")
    );
    assert_eq!(
        sha3_384_bits(message).map_err(|_| "SHA3-384")?.as_bytes(),
        &hex::<48>(
            "737c9b491885e9bf7428e792741a7bf8dca9653471c3e148473f2c236b6a0a6455eb1dce9f779b4b6b237fef171b1c64"
        )
    );
    assert_eq!(
        sha3_512_bits(message).map_err(|_| "SHA3-512")?.as_bytes(),
        &hex::<64>(
            "a13e01494114c09800622a70288c432121ce70039d753cadd2e006e4d961cb27544c1481e5814bdceb53be6733d5e099795e5e81918addb058e22a9f24883f37"
        )
    );

    let mut output128 = [0_u8; 64];
    let destination128 = Fips202Output::new(&mut output128, 8).map_err(|_| "SHAKE128 shape")?;
    shake128_bits(message, destination128).map_err(|_| "SHAKE128")?;
    assert_eq!(
        output128,
        hex::<64>(
            "2e0abfba83e6720bfbc225ff6b7ab9ffce58ba027ee3d898764fef287ddeccca3e6e5998411e7ddb32f67538f500b18c8c97c452c370ea2cf0afca3e05de7e4d"
        )
    );
    let mut output256 = [0_u8; 64];
    let destination256 = Fips202Output::new(&mut output256, 8).map_err(|_| "SHAKE256 shape")?;
    shake256_bits(message, destination256).map_err(|_| "SHAKE256")?;
    assert_eq!(
        output256,
        hex::<64>(
            "48a5c11abaeeff092f3646ef0d6b3d3ff76c2f55f9c732ac6470c03764008212e21b1467778b181989f88858211b45df8799cf961f800dfac99e644039e2979a"
        )
    );
    Ok(())
}

#[test]
fn low_bit_canonical_representation_is_exact() -> TestResult {
    assert_eq!(
        Fips202BitString::new(&[], 0)
            .map_err(|_| "empty")?
            .bit_len(),
        0
    );
    assert_eq!(
        Fips202BitString::new(&[0xa5], 8)
            .map_err(|_| "byte")?
            .bit_len(),
        8
    );
    assert_eq!(
        Fips202BitString::new(&[0x05], 3)
            .map_err(|_| "tail")?
            .bit_len(),
        3
    );
    assert!(matches!(
        Fips202BitString::new(&[], 1),
        Err(Fips202BitsError::InvalidValidBitCount)
    ));
    assert!(matches!(
        Fips202BitString::new(&[0], 0),
        Err(Fips202BitsError::InvalidValidBitCount)
    ));
    assert!(matches!(
        Fips202BitString::new(&[0x80], 7),
        Err(Fips202BitsError::NonZeroUnusedBits)
    ));
    let mut empty = [];
    assert!(Fips202Output::new(&mut empty, 0).is_ok());
    assert!(matches!(
        Fips202Output::new(&mut empty, 8),
        Err(Fips202BitsError::InvalidValidBitCount)
    ));
    Ok(())
}

#[test]
fn every_byte_aligned_bit_api_equals_the_frozen_byte_api() -> TestResult {
    let messages: [&[u8]; 5] = [b"", b"a", b"abc", &[0xa5; 72], &[0x5a; 169]];
    for message in messages {
        let valid = if message.is_empty() { 0 } else { 8 };
        let bits = Fips202BitString::new(message, valid).map_err(|_| "aligned input")?;
        assert_eq!(
            sha3_224_bits(bits).map_err(|_| "bit 224")?,
            sha3_224(message).map_err(|_| "byte 224")?
        );
        assert_eq!(
            sha3_256_bits(bits).map_err(|_| "bit 256")?,
            sha3_256(message).map_err(|_| "byte 256")?
        );
        assert_eq!(
            sha3_384_bits(bits).map_err(|_| "bit 384")?,
            sha3_384(message).map_err(|_| "byte 384")?
        );
        assert_eq!(
            sha3_512_bits(bits).map_err(|_| "bit 512")?,
            sha3_512(message).map_err(|_| "byte 512")?
        );
        compare_aligned_shake(message, bits)?;
    }
    Ok(())
}

fn compare_aligned_shake(message: &[u8], bits: Fips202BitString<'_>) -> TestResult {
    let mut byte128 = [0_u8; 193];
    let mut bit128 = [0_u8; 193];
    shake128(message, &mut byte128).map_err(|_| "byte shake128")?;
    let destination = Fips202Output::new(&mut bit128, 8).map_err(|_| "output128")?;
    shake128_bits(bits, destination).map_err(|_| "bit shake128")?;
    assert_eq!(bit128, byte128);
    let mut byte256 = [0_u8; 193];
    let mut bit256 = [0_u8; 193];
    shake256(message, &mut byte256).map_err(|_| "byte shake256")?;
    let destination = Fips202Output::new(&mut bit256, 8).map_err(|_| "output256")?;
    shake256_bits(bits, destination).map_err(|_| "bit shake256")?;
    assert_eq!(bit256, byte256);
    Ok(())
}

#[test]
fn every_tail_width_and_suffix_rate_collision_is_stable() -> TestResult {
    for valid in 1..8 {
        for length in [71_usize, 72, 103, 104, 135, 136, 143, 144, 167, 168] {
            check_boundary(valid, length)?;
        }
    }
    Ok(())
}

fn check_boundary(valid: u8, length: usize) -> TestResult {
    let mut message = [0_u8; 169];
    let inclusive = message.get_mut(..=length).ok_or("inclusive boundary")?;
    for (position, byte) in inclusive.iter_mut().enumerate() {
        *byte = u8::try_from(position)
            .map_err(|_| "position")?
            .wrapping_mul(29);
    }
    let tail_byte = message.get_mut(length).ok_or("tail byte")?;
    *tail_byte &= low_mask(valid);
    let whole_bytes = message.get(..=length).ok_or("whole bytes")?;
    let tail_bytes = message.get(length..=length).ok_or("tail bytes")?;
    let prefix = message.get(..length).ok_or("prefix")?;
    let whole = Fips202BitString::new(whole_bytes, valid).map_err(|_| "whole")?;
    let tail = Fips202BitString::new(tail_bytes, valid).map_err(|_| "tail")?;

    let mut sha256 = Sha3_256::new();
    sha256.update(prefix).map_err(|_| "update")?;
    assert_eq!(
        sha256.finalize_bits(tail).map_err(|_| "stream bit")?,
        sha3_256_bits(whole).map_err(|_| "one-shot bit")?
    );

    let mut shake = Shake128::new();
    shake.update(prefix).map_err(|_| "shake update")?;
    let mut reader = shake.finalize_bits_xof(tail).map_err(|_| "shake final")?;
    let mut streamed = [0_u8; 211];
    reader.squeeze(&mut streamed).map_err(|_| "shake squeeze")?;
    let mut one_shot = [0_u8; 211];
    let destination = Fips202Output::new(&mut one_shot, 8).map_err(|_| "destination")?;
    shake128_bits(whole, destination).map_err(|_| "one shot")?;
    assert_eq!(streamed, one_shot);
    Ok(())
}

#[test]
fn final_partial_shake_output_is_canonical_and_partitionable() -> TestResult {
    let input = Fips202BitString::new(&[0x13], 5).map_err(|_| "input")?;
    for valid in 1..8 {
        check_partial_output128(input, valid)?;
        check_partial_output256(input, valid)?;
    }
    Ok(())
}

fn check_partial_output128(input: Fips202BitString<'_>, valid: u8) -> TestResult {
    let mut expected = [0_u8; 34];
    let destination = Fips202Output::new(&mut expected, 8).map_err(|_| "expected128")?;
    shake128_bits(input, destination).map_err(|_| "shake128 expected")?;
    let mut reader = Shake128::new()
        .finalize_bits_xof(input)
        .map_err(|_| "reader128")?;
    let mut prefix = [0_u8; 33];
    reader.squeeze(&mut prefix).map_err(|_| "prefix128")?;
    let mut tail = [0xff_u8; 1];
    let destination = Fips202Output::new(&mut tail, valid).map_err(|_| "tail128")?;
    reader
        .squeeze_final_bits(destination)
        .map_err(|_| "final128")?;
    assert_eq!(
        prefix.as_slice(),
        expected.get(..33).ok_or("expected prefix128")?
    );
    assert_eq!(
        tail.first().copied(),
        expected.get(33).copied().map(|byte| byte & low_mask(valid))
    );
    Ok(())
}

fn check_partial_output256(input: Fips202BitString<'_>, valid: u8) -> TestResult {
    let mut expected = [0_u8; 34];
    let destination = Fips202Output::new(&mut expected, 8).map_err(|_| "expected256")?;
    shake256_bits(input, destination).map_err(|_| "shake256 expected")?;
    let mut reader = Shake256::new()
        .finalize_bits_xof(input)
        .map_err(|_| "reader256")?;
    let mut prefix = [0_u8; 33];
    reader.squeeze(&mut prefix).map_err(|_| "prefix256")?;
    let mut tail = [0xff_u8; 1];
    let destination = Fips202Output::new(&mut tail, valid).map_err(|_| "tail256")?;
    reader
        .squeeze_final_bits(destination)
        .map_err(|_| "final256")?;
    assert_eq!(
        prefix.as_slice(),
        expected.get(..33).ok_or("expected prefix256")?
    );
    assert_eq!(
        tail.first().copied(),
        expected.get(33).copied().map(|byte| byte & low_mask(valid))
    );
    Ok(())
}

fn hex<const N: usize>(input: &str) -> [u8; N] {
    let mut output = [0_u8; N];
    for (target, pair) in output.iter_mut().zip(input.as_bytes().chunks_exact(2)) {
        if let [high, low] = pair {
            *target = nibble(*high).saturating_mul(16) | nibble(*low);
        }
    }
    output
}

fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value.saturating_sub(b'0'),
        b'a'..=b'f' => value.saturating_sub(b'a').saturating_add(10),
        _ => 0,
    }
}

fn low_mask(valid: u8) -> u8 {
    u8::MAX
        .checked_shr(u32::from(8_u8.saturating_sub(valid)))
        .unwrap_or_default()
}
