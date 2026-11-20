//! Frozen AESAVS ECB campaigns for the private secondary engine.
//! This is primitive testing, not an ECB mode API or fault qualification.
extern crate std;
use super::{Error, cipher_tests::hex, schedule::Schedule};
use std::{format, vec::Vec};

pub(super) struct Record {
    pub(super) key: Vec<u8>,
    pub(super) input: Vec<u8>,
    pub(super) expected: Vec<u8>,
    pub(super) inverse: bool,
}

fn field<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    prefix: &str,
    expected_bytes: usize,
) -> Result<Vec<u8>, Error> {
    let encoded = lines
        .next()
        .and_then(|line| line.strip_prefix(prefix))
        .ok_or(Error::SecretMemory)?;
    let bytes = hex(encoded)?;
    if bytes.len() != expected_bytes {
        return Err(Error::SecretMemory);
    }
    Ok(bytes)
}

pub(super) fn records(text: &str, width: usize, monte_carlo: bool) -> Result<Vec<Record>, Error> {
    if !matches!(width, 16 | 24 | 32) {
        return Err(Error::SecretMemory);
    }
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'));
    let mut result = Vec::new();
    for (section, inverse, input, output) in [
        ("[ENCRYPT]", false, "PLAINTEXT = ", "CIPHERTEXT = "),
        ("[DECRYPT]", true, "CIPHERTEXT = ", "PLAINTEXT = "),
    ] {
        if lines.next() != Some(section) {
            return Err(Error::SecretMemory);
        }
        for index in 0usize..if monte_carlo { 100 } else { 10 } {
            if lines.next() != Some(format!("COUNT = {index}").as_str()) {
                return Err(Error::SecretMemory);
            }
            let bytes = if monte_carlo {
                16
            } else {
                index
                    .checked_add(1usize)
                    .and_then(|count| count.checked_mul(16))
                    .ok_or(Error::SecretMemory)?
            };
            result.push(Record {
                inverse,
                key: field(&mut lines, "KEY = ", width)?,
                input: field(&mut lines, input, bytes)?,
                expected: field(&mut lines, output, bytes)?,
            });
        }
    }
    if lines.next().is_some() {
        return Err(Error::SecretMemory);
    }
    Ok(result)
}

pub(super) const CORPORA: [(&str, usize); 3] = [
    (
        include_str!("../../../../assurance/aes-avs/fixtures/ECBMMT128.rsp"),
        16,
    ),
    (
        include_str!("../../../../assurance/aes-avs/fixtures/ECBMMT192.rsp"),
        24,
    ),
    (
        include_str!("../../../../assurance/aes-avs/fixtures/ECBMMT256.rsp"),
        32,
    ),
];

pub(super) const MONTE_CARLO_CORPORA: [(&str, usize); 3] = [
    (
        include_str!("../../../../assurance/aes-avs/fixtures/ECBMCT128.rsp"),
        16,
    ),
    (
        include_str!("../../../../assurance/aes-avs/fixtures/ECBMCT192.rsp"),
        24,
    ),
    (
        include_str!("../../../../assurance/aes-avs/fixtures/ECBMCT256.rsp"),
        32,
    ),
];

#[test]
fn all_frozen_multiblock_records_both_directions_and_schedule_reuse() -> Result<(), Error> {
    let mut total_records = 0usize;
    let mut total_blocks = 0usize;
    for (text, width) in CORPORA {
        let cases = records(text, width, false)?;
        assert_eq!(cases.len(), 20);
        total_records = total_records
            .checked_add(cases.len())
            .ok_or(Error::SecretMemory)?;
        for case in cases {
            let mut schedule = Schedule::new();
            schedule.expand(&case.key)?;
            let (inputs, input_remainder) = case.input.as_chunks::<16>();
            let (expected, expected_remainder) = case.expected.as_chunks::<16>();
            assert!(input_remainder.is_empty() && expected_remainder.is_empty());
            assert_eq!(inputs.len(), expected.len());
            for (input, expected) in inputs.iter().zip(expected) {
                for _ in 0..2 {
                    let mut output = [0xa5; 16];
                    schedule.transform(input, &mut output, case.inverse)?;
                    assert_eq!(&output, expected, "key bytes {width}, block {total_blocks}");
                }
                total_blocks = total_blocks.checked_add(1).ok_or(Error::SecretMemory)?;
            }
        }
    }
    assert_eq!(total_records, 60);
    assert_eq!(total_blocks, 330);
    Ok(())
}

#[test]
fn multiblock_parser_rejects_missing_extra_and_wrong_width_records() {
    for (text, width) in CORPORA {
        assert!(records(text, 15, false).is_err());
        assert!(records(text, if width == 16 { 24 } else { 16 }, false).is_err());
        for malformed in [
            text.replacen("COUNT = 0", "COUNT = 1", 1),
            text.replacen("[DECRYPT]", "[ENCRYPT]", 1),
            text.replacen("KEY = ", "KEY = 00", 1),
            text.replacen("PLAINTEXT = ", "PLAINTEXT = 00", 1),
            text.replacen("CIPHERTEXT = ", "CIPHERTEXT = gg", 1),
            format!("{text}\nCOUNT = 10"),
        ] {
            assert!(records(&malformed, width, false).is_err());
        }
        let lines: Vec<_> = text.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let missing = lines
                .iter()
                .enumerate()
                .filter_map(|(current, line)| (current != index).then_some(*line))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                records(&missing, width, false).is_err(),
                "missing line {index}"
            );
        }
    }
}

pub(super) fn next_key(key: &[u8], previous: &[u8; 16], last: &[u8; 16]) -> Result<Vec<u8>, Error> {
    if !matches!(key.len(), 16 | 24 | 32) {
        return Err(Error::SecretMemory);
    }
    let mut joined = [0; 32];
    joined[..16].copy_from_slice(previous);
    joined[16..].copy_from_slice(last);
    let offset = joined
        .len()
        .checked_sub(key.len())
        .ok_or(Error::SecretMemory)?;
    let update = joined.get(offset..).ok_or(Error::SecretMemory)?;
    Ok(key.iter().zip(update).map(|(old, new)| old ^ new).collect())
}

#[test]
fn monte_carlo_parser_and_key_update_reject_invalid_inputs() -> Result<(), Error> {
    for (text, width) in MONTE_CARLO_CORPORA {
        assert_eq!(records(text, width, true)?.len(), 200);
        assert!(records(text, 15, true).is_err());
        assert!(records(text, if width == 16 { 24 } else { 16 }, true).is_err());
        assert!(records(text, width, false).is_err());
        for malformed in [
            text.replacen("COUNT = 0", "COUNT = 1", 1),
            text.replacen("COUNT = 99", "COUNT = 98", 1),
            text.replacen("[DECRYPT]", "[ENCRYPT]", 1),
            text.replacen("KEY = ", "KEY = 00", 1),
            text.replacen("PLAINTEXT = ", "PLAINTEXT = 00", 1),
            text.replacen("CIPHERTEXT = ", "CIPHERTEXT = gg", 1),
            format!("{text}\nCOUNT = 100"),
        ] {
            assert!(records(&malformed, width, true).is_err());
        }
    }
    assert!(next_key(&[0; 15], &[0; 16], &[0; 16]).is_err());
    let previous = [0x11; 16];
    let last = [0x22; 16];
    assert_eq!(next_key(&[0; 16], &previous, &last)?, [0x22; 16]);
    let mut expected_192 = [0x22; 24];
    expected_192[..8].fill(0x11);
    assert_eq!(next_key(&[0; 24], &previous, &last)?, expected_192);
    let mut expected_256 = [0x22; 32];
    expected_256[..16].fill(0x11);
    assert_eq!(next_key(&[0; 32], &previous, &last)?, expected_256);
    let mut xor_expected = [0x78; 24];
    xor_expected[..8].fill(0x4b);
    assert_eq!(next_key(&[0x5a; 24], &previous, &last)?, xor_expected);
    Ok(())
}

#[test]
#[ignore = "explicit 600,000-block optimized AESAVS campaign; run --release --ignored"]
fn all_frozen_monte_carlo_chains_both_directions() -> Result<(), Error> {
    let mut total_records = 0usize;
    let mut total_blocks = 0usize;
    for (text, width) in MONTE_CARLO_CORPORA {
        let cases = records(text, width, true)?;
        let (sections, remainder) = cases.as_chunks::<100>();
        assert!(remainder.is_empty() && sections.len() == 2);
        for (inverse, section) in [false, true].into_iter().zip(sections) {
            let mut key = section[0].key.clone();
            let mut input: [u8; 16] = section[0]
                .input
                .as_slice()
                .try_into()
                .map_err(|_| Error::SecretMemory)?;
            for (index, case) in section.iter().enumerate() {
                assert!(
                    case.inverse == inverse && case.key == key && case.input == input,
                    "MCT input/key chain mismatch at width {width}, direction {inverse}, record {index}"
                );
                let mut schedule = Schedule::new();
                schedule.expand(&key)?;
                let mut current = input;
                let mut previous = input;
                for _ in 0..1000 {
                    previous = current;
                    let mut output = [0xa5; 16];
                    schedule.transform(&current, &mut output, inverse)?;
                    current = output;
                    total_blocks = total_blocks.checked_add(1).ok_or(Error::SecretMemory)?;
                }
                assert!(
                    case.expected == current,
                    "MCT final block mismatch at width {width}, direction {inverse}, record {index}"
                );
                key = next_key(&key, &previous, &current)?;
                input = current;
                total_records = total_records.checked_add(1).ok_or(Error::SecretMemory)?;
            }
        }
    }
    assert_eq!(total_records, 600);
    assert_eq!(total_blocks, 600_000);
    Ok(())
}
