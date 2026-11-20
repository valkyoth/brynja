//! Public frozen-answer tests. No fault-profile qualification is implied.
extern crate std;
use super::{Error, Planes, read, schedule::Schedule};
use std::{format, vec::Vec};

pub(super) fn hex(text: &str) -> Result<Vec<u8>, Error> {
    if !text.len().is_multiple_of(2) || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::SecretMemory);
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let pair = core::str::from_utf8(pair).map_err(|_| Error::SecretMemory)?;
            u8::from_str_radix(pair, 16).map_err(|_| Error::SecretMemory)
        })
        .collect()
}

fn block(bytes: &[u8]) -> Result<[u8; 16], Error> {
    bytes.try_into().map_err(|_| Error::SecretMemory)
}

#[test]
fn fips_blocks_all_widths_and_directions() -> Result<(), Error> {
    let input = block(&hex("00112233445566778899aabbccddeeff")?)?;
    for (key, expected) in [
        (
            "000102030405060708090a0b0c0d0e0f",
            "69c4e0d86a7b0430d8cdb78070b4c55a",
        ),
        (
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "dda97ca4864cdfe06eaf70a0ec0d7191",
        ),
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "8ea2b7ca516745bfeafc49904b496089",
        ),
    ] {
        let mut schedule = Schedule::new();
        schedule.expand(&hex(key)?)?;
        let expected = block(&hex(expected)?)?;
        let mut output = [0xa5; 16];
        schedule.transform(&input, &mut output, false)?;
        assert_eq!(output, expected);
        schedule.transform(&expected, &mut output, true)?;
        assert_eq!(output, input);
    }
    Ok(())
}

fn multiply_oracle(a: u8, b: u8) -> Result<u8, Error> {
    // Test-only carryless polynomial product and long division, not the
    // implementation's bit-plane XOR network or primary arithmetic helpers.
    let mut product = 0u16;
    for bit in 0..8 {
        if b & (1 << bit) != 0 {
            product ^= u16::from(a) << bit;
        }
    }
    for bit in (8usize..16).rev() {
        if product & (1 << bit) != 0 {
            product ^= 0x11b << bit.wrapping_sub(8);
        }
    }
    u8::try_from(product).map_err(|_| Error::SecretMemory)
}

#[test]
fn linear_layers_match_independent_matrices_for_every_single_byte() -> Result<(), Error> {
    let forward = [2, 3, 1, 1];
    let backward = [14, 11, 13, 9];
    for inverse in [false, true] {
        let coefficients = if inverse { &backward } else { &forward };
        let shift_sources = if inverse {
            [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3]
        } else {
            [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
        };
        for lane in 0usize..16 {
            for value in 0..=u8::MAX {
                let mut input = [0; 16];
                *input.get_mut(lane).ok_or(Error::SecretMemory)? = value;
                let mut state = Planes::new();
                state.load(&input)?;
                state.mix_columns(inverse)?;
                let mut actual = [0; 16];
                state.store(&mut actual)?;
                let mut expected = [0; 16];
                for row in 0usize..4 {
                    let coefficient = read(
                        coefficients,
                        (lane % 4).wrapping_add(4).wrapping_sub(row) % 4,
                    )?;
                    *expected
                        .get_mut((lane / 4).wrapping_mul(4).wrapping_add(row))
                        .ok_or(Error::SecretMemory)? = multiply_oracle(value, coefficient)?;
                }
                assert_eq!(actual, expected);
                state.mix_columns(!inverse)?;
                state.store(&mut actual)?;
                assert_eq!(actual, input);
                state.shift_rows(inverse)?;
                state.store(&mut actual)?;
                for (byte, source) in actual.iter().zip(shift_sources) {
                    assert_eq!(*byte, read(&input, source)?);
                }
                state.shift_rows(!inverse)?;
                state.store(&mut actual)?;
                assert_eq!(actual, input);
            }
        }
        let input = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let expected = if inverse {
            [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3]
        } else {
            [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
        };
        let mut state = Planes::new();
        state.load(&input)?;
        state.shift_rows(inverse)?;
        let mut actual = [0; 16];
        state.store(&mut actual)?;
        assert_eq!(actual, expected);
        state.shift_rows(!inverse)?;
        state.store(&mut actual)?;
        assert_eq!(actual, input);
    }
    Ok(())
}

struct Case {
    key: Vec<u8>,
    input: [u8; 16],
    expected: [u8; 16],
    inverse: bool,
}

fn corpus(text: &str, width: usize, population: usize) -> Result<Vec<Case>, Error> {
    if !matches!(width, 16 | 24 | 32) || population == 0 {
        return Err(Error::SecretMemory);
    }
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with('#'));
    let mut cases = Vec::new();
    for (section, inverse, input, expected) in [
        ("[ENCRYPT]", false, "PLAINTEXT = ", "CIPHERTEXT = "),
        ("[DECRYPT]", true, "CIPHERTEXT = ", "PLAINTEXT = "),
    ] {
        if lines.next() != Some(section) {
            return Err(Error::SecretMemory);
        }
        for count in 0..population {
            if lines.next() != Some(format!("COUNT = {count}").as_str()) {
                return Err(Error::SecretMemory);
            }
            let mut field = |prefix| {
                hex(lines
                    .next()
                    .and_then(|s| s.strip_prefix(prefix))
                    .ok_or(Error::SecretMemory)?)
            };
            let key = field("KEY = ")?;
            if key.len() != width {
                return Err(Error::SecretMemory);
            }
            cases.push(Case {
                key,
                input: block(&field(input)?)?,
                expected: block(&field(expected)?)?,
                inverse,
            });
        }
    }
    if lines.next().is_some() {
        return Err(Error::SecretMemory);
    }
    Ok(cases)
}

macro_rules! files {
    ($bits:literal, $width:literal, $gfs:literal, $sbox:literal, $keys:literal) => {
        [
            (
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/aes",
                    $bits,
                    "/ECBGFSbox",
                    $bits,
                    ".rsp"
                )),
                $width,
                $gfs,
            ),
            (
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/aes",
                    $bits,
                    "/ECBKeySbox",
                    $bits,
                    ".rsp"
                )),
                $width,
                $sbox,
            ),
            (
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/aes",
                    $bits,
                    "/ECBVarKey",
                    $bits,
                    ".rsp"
                )),
                $width,
                $keys,
            ),
            (
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/aes",
                    $bits,
                    "/ECBVarTxt",
                    $bits,
                    ".rsp"
                )),
                $width,
                128,
            ),
        ]
    };
}

const CORPORA: [[(&str, usize, usize); 4]; 3] = [
    files!("128", 16, 7, 21, 128),
    files!("192", 24, 6, 24, 192),
    files!("256", 32, 5, 16, 256),
];

#[test]
fn all_2078_frozen_nist_kats_both_directions_and_schedule_reuse() -> Result<(), Error> {
    let mut counts = Vec::new();
    for files in CORPORA {
        let mut count = 0usize;
        for (text, width, population) in files {
            for case in corpus(text, width, population)? {
                let mut schedule = Schedule::new();
                schedule.expand(&case.key)?;
                for _ in 0..2 {
                    let mut output = [0xa5; 16];
                    schedule.transform(&case.input, &mut output, case.inverse)?;
                    assert_eq!(output, case.expected, "key bytes {width}, case {count}");
                }
                count = count.checked_add(1).ok_or(Error::SecretMemory)?;
            }
        }
        counts.push(count);
    }
    assert_eq!(counts, [568, 700, 810]);
    Ok(())
}

#[test]
fn corpus_rejects_missing_extra_wrong_width_and_malformed_records() -> Result<(), Error> {
    let (text, width, population) = *CORPORA
        .first()
        .and_then(|f| f.first())
        .ok_or(Error::SecretMemory)?;
    assert!(corpus(text, width, 0).is_err());
    assert!(corpus(text, 24, population).is_err());
    assert!(corpus(text, width, population.wrapping_add(1)).is_err());
    assert!(corpus(text, width, population.wrapping_sub(1)).is_err());
    for pattern in [
        "COUNT = 0",
        "[DECRYPT]",
        "KEY = ",
        "PLAINTEXT = ",
        "CIPHERTEXT = ",
    ] {
        assert!(corpus(&text.replacen(pattern, "bad", 1), width, population).is_err());
    }
    assert!(corpus(&format!("{text}\nCOUNT = 99"), width, population).is_err());
    assert!(hex("0").is_err());
    assert!(hex("gg").is_err());
    assert!(block(&[0; 15]).is_err());
    Ok(())
}

#[test]
fn invalid_width_unexpanded_schedule_and_reexpansion() -> Result<(), Error> {
    let mut schedule = Schedule::new();
    let mut output = [0xa5; 16];
    for inverse in [false, true] {
        assert!(schedule.transform(&[0; 16], &mut output, inverse).is_err());
        assert_eq!(output, [0xa5; 16]);
    }
    for length in 0..=40 {
        if !matches!(length, 16 | 24 | 32) {
            assert!(schedule.expand(&std::vec![0; length]).is_err());
        }
    }
    schedule.expand(&[0x5a; 32])?;
    schedule.expand(&[0; 16])?;
    for unused in schedule.keys.iter().skip(11) {
        assert_eq!(unused.0.0, [0; 16]);
    }
    schedule.transform(&[0; 16], &mut output, false)?;
    assert_eq!(output, block(&hex("66e94bd4ef8a2c3b884cfa59ca342b2e")?)?);
    Ok(())
}

#[test]
fn complete_fips_appendix_a_schedules_all_widths() -> Result<(), Error> {
    // FIPS 197 Appendix A. Frozen answers, not another expansion's output.
    for (width, size, encoded) in [
        (
            16,
            176,
            "2b7e151628aed2a6abf7158809cf4f3c
        a0fafe1788542cb123a339392a6c7605 f2c295f27a96b9435935807a7359f67f
        3d80477d4716fe3e1e237e446d7a883b ef44a541a8525b7fb671253bdb0bad00
        d4d1c6f87c839d87caf2b8bc11f915bc 6d88a37a110b3efddbf98641ca0093fd
        4e54f70e5f5fc9f384a64fb24ea6dc4f ead27321b58dbad2312bf5607f8d292f
        ac7766f319fadc2128d12941575c006e d014f9a8c9ee2589e13f0cc8b6630ca6",
        ),
        (
            24,
            208,
            "8e73b0f7 da0e6452 c810f32b 809079e5 62f8ead2 522c6b7b
        fe0c91f7 2402f5a5 ec12068e 6c827f6b 0e7a95b9 5c56fec2
        4db7b4bd 69b54118 85a74796 e92538fd e75fad44 bb095386
        485af057 21efb14f a448f6d9 4d6dce24 aa326360 113b30e6
        a25e7ed5 83b1cf9a 27f93943 6a94f767 c0a69407 d19da4e1
        ec1786eb 6fa64971 485f7032 22cb8755 e26d1352 33f0b7b3
        40beeb28 2f18a259 6747d26b 458c553e a7e1466c 9411f1df
        821f750a ad07d753 ca400538 8fcc5006 282d166a bc3ce7b5
        e98ba06f 448c773c 8ecc7204 01002202",
        ),
        (
            32,
            240,
            "603deb10 15ca71be 2b73aef0 857d7781 1f352c07 3b6108d7 2d9810a3 0914dff4
        9ba35411 8e6925af a51a8b5f 2067fcde a8b09c1a 93d194cd be49846e b75d5b9a
        d59aecb8 5bf3c917 fee94248 de8ebe96 b5a9328a 2678a647 98312229 2f6c79b3
        812c81ad dadf48ba 24360af2 fab8b464 98c5bfc9 bebd198e 268c3ba7 09e04214
        68007bac b2df3316 96e939e4 6c518d80 c814e204 76a9fb8a 5025c02d 59c58239
        de136967 6ccc5a71 fa256395 9674ee15 5886ca5d 2e2f31d7 7e0af1fa 27cf73c3
        749c47ab 18501dda e2757e4f 7401905a cafaaae3 e4d59b34 9adf6ace bd10190d
        fe4890d1 e6188d0b 046df344 706c631e",
        ),
    ] {
        let encoded: std::string::String = encoded.split_whitespace().collect();
        let expected = hex(&encoded)?;
        assert_eq!(expected.len(), size);
        let mut schedule = Schedule::new();
        schedule.expand(expected.get(..width).ok_or(Error::SecretMemory)?)?;
        let mut actual = Vec::new();
        for round in schedule.keys.iter().take(size / 16) {
            let mut bytes = [0; 16];
            round.store(&mut bytes)?;
            actual.extend_from_slice(&bytes);
        }
        assert_eq!(actual, expected);
    }
    Ok(())
}
