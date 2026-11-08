//! AESAVS ECB response files applied to public single-block APIs only.
//! No mode API, CAVP validation, timing or physical-fault claim.
#![forbid(unsafe_code)]

use brynja_aes_public_api_fixture::aes::*;

type Check<T> = Result<T, Box<dyn std::error::Error>>;
const INNER: usize = 1000; // AESAVS section 6.4.1, j=0..999.

#[derive(Debug)]
struct Record<const K: usize> {
    inverse: bool,
    key: [u8; K],
    input: Vec<u8>,
    expected: Vec<u8>,
}

fn hex(text: &str, bytes: usize) -> Check<Vec<u8>> {
    if text.len() != bytes * 2 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid hex length or digit".into());
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok(u8::from_str_radix(core::str::from_utf8(pair)?, 16)?))
        .collect()
}

fn field(line: Option<&str>, prefix: &str, bytes: usize) -> Check<Vec<u8>> {
    hex(
        line.and_then(|s| s.strip_prefix(prefix))
            .ok_or("missing field")?,
        bytes,
    )
}

fn records<const K: usize>(text: &str, monte_carlo: bool) -> Check<Vec<Record<K>>> {
    if !matches!(K, 16 | 24 | 32) {
        return Err("unsupported AES key width".into());
    }
    let count = if monte_carlo { 100 } else { 10 };
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with('#'));
    let mut result = Vec::new();
    for (section, inverse, input, output) in [
        ("[ENCRYPT]", false, "PLAINTEXT = ", "CIPHERTEXT = "),
        ("[DECRYPT]", true, "CIPHERTEXT = ", "PLAINTEXT = "),
    ] {
        if lines.next() != Some(section) {
            return Err("wrong section".into());
        }
        for index in 0..count {
            if lines.next() != Some(format!("COUNT = {index}").as_str()) {
                return Err("wrong record number".into());
            }
            let bytes = if monte_carlo { 16 } else { (index + 1) * 16 };
            result.push(Record {
                inverse,
                key: field(lines.next(), "KEY = ", K)?
                    .try_into()
                    .map_err(|_| "key width")?,
                input: field(lines.next(), input, bytes)?,
                expected: field(lines.next(), output, bytes)?,
            });
        }
    }
    if lines.next().is_some() {
        return Err("unexpected trailing data".into());
    }
    Ok(result)
}

fn next_key<const K: usize>(key: &[u8; K], previous: &[u8; 16], last: &[u8; 16]) -> Check<[u8; K]> {
    // 192-bit update: last 64 bits of the penultimate block || last block.
    // 256-bit update: complete penultimate block || last block.
    if !matches!(K, 16 | 24 | 32) {
        return Err("unsupported key update width".into());
    }
    let mut joined = [0; 32];
    joined[..16].copy_from_slice(previous);
    joined[16..].copy_from_slice(last);
    Ok(core::array::from_fn(|i| key[i] ^ joined[32 - K + i]))
}

fn iterate(
    mut input: [u8; 16],
    mut block: impl FnMut(&[u8; 16]) -> Check<[u8; 16]>,
) -> Check<([u8; 16], [u8; 16])> {
    let mut previous = input;
    for _ in 0..INNER {
        previous = input;
        input = block(&input)?;
    }
    Ok((previous, input))
}

fn campaign<const K: usize>(
    vectors: &[Record<K>],
    mut run: impl FnMut(&[u8; K], &[u8; 16], bool) -> Check<([u8; 16], [u8; 16])>,
) -> Check<()> {
    if vectors.len() != 200 {
        return Err("Monte Carlo population changed".into());
    }
    for (inverse, section) in [false, true].into_iter().zip(vectors.as_chunks::<100>().0) {
        let mut key = section[0].key;
        let mut input: [u8; 16] = section[0].input.as_slice().try_into()?;
        for (index, record) in section.iter().enumerate() {
            // Do not restart from each published key: check the complete chain.
            if record.inverse != inverse || record.key != key || record.input != input {
                return Err(
                    format!("MCT chain mismatch at record {index}, inverse={inverse}").into(),
                );
            }
            let (previous, last) = run(&key, &input, inverse)?;
            if record.expected != last {
                return Err(
                    format!("MCT output mismatch at record {index}, inverse={inverse}").into(),
                );
            }
            key = next_key(&key, &previous, &last)?;
            input = last;
        }
    }
    Ok(())
}

macro_rules! width {
    ($module:ident, $key:ident, $cached:ident, $k:literal, $s:literal, $bits:literal) => {
        mod $module {
            use super::*;
            const MCT: &str = include_str!(concat!("fixtures/ECBMCT", $bits, ".rsp"));
            const MMT: &str = include_str!(concat!("fixtures/ECBMMT", $bits, ".rsp"));

            #[test]
            fn monte_carlo() -> Check<()> {
                let vectors = records::<$k>(MCT, true)?;
                for cached in [false, true] {
                    campaign(&vectors, |bytes, input, inverse| {
                        let mut storage = [0xa5; $k];
                        let mut schedule = [0xa5; $s];
                        let key = $key::new(bytes, &mut storage).map_err(|e| format!("{e:?}"))?;
                        let expanded =
                            $cached::new(bytes, &mut schedule).map_err(|e| format!("{e:?}"))?;
                        let result = iterate(*input, |input| {
                            let mut output = [0xa5; 16];
                            let secret = match (cached, inverse) {
                                (false, false) => key.encrypt_block(input, &mut output),
                                (false, true) => key.decrypt_block(input, &mut output),
                                (true, false) => expanded.encrypt_block(input, &mut output),
                                (true, true) => expanded.decrypt_block(input, &mut output),
                            }
                            .map_err(|e| format!("{e:?}"))?;
                            let block = secret.expose().try_into()?;
                            secret.clear();
                            assert_eq!(output, [0; 16]);
                            Ok(block)
                        })?;
                        key.clear();
                        expanded.clear();
                        assert_eq!(storage, [0; $k]);
                        assert_eq!(schedule, [0; $s]);
                        Ok(result)
                    })?;
                }
                println!(concat!(
                    "AESAVS_MCT: ",
                    $bits,
                    " 200 records; 1000 iterations; 2 owners; 400000 block operations"
                ));
                Ok(())
            }

            #[test]
            fn multiblock() -> Check<()> {
                let vectors = records::<$k>(MMT, false)?;
                assert_eq!(vectors.len(), 20);
                let mut blocks = 0;
                for record in vectors {
                    let mut storage = [0xa5; $k];
                    let mut schedule = [0xa5; $s];
                    let key = $key::new(&record.key, &mut storage).map_err(|e| format!("{e:?}"))?;
                    let expanded =
                        $cached::new(&record.key, &mut schedule).map_err(|e| format!("{e:?}"))?;
                    // ECB corpus semantics only: independent consecutive blocks,
                    // no padding, IV, chaining, authentication or mode API.
                    for (input, expected) in record
                        .input
                        .chunks_exact(16)
                        .zip(record.expected.chunks_exact(16))
                    {
                        let input: &[u8; 16] = input.try_into()?;
                        for cached in [false, true] {
                            let mut output = [0xa5; 16];
                            let secret = match (cached, record.inverse) {
                                (false, false) => key.encrypt_block(input, &mut output),
                                (false, true) => key.decrypt_block(input, &mut output),
                                (true, false) => expanded.encrypt_block(input, &mut output),
                                (true, true) => expanded.decrypt_block(input, &mut output),
                            }
                            .map_err(|e| format!("{e:?}"))?;
                            assert_eq!(secret.expose(), expected);
                            secret.clear();
                            assert_eq!(output, [0; 16]);
                            if !record.inverse {
                                if cached {
                                    expanded
                                        .encrypt_block_public(
                                            input,
                                            &mut output,
                                            PublicCiphertext::acknowledge(),
                                        )
                                        .map_err(|e| format!("{e:?}"))?;
                                } else {
                                    key.encrypt_block_public(
                                        input,
                                        &mut output,
                                        PublicCiphertext::acknowledge(),
                                    )
                                    .map_err(|e| format!("{e:?}"))?;
                                }
                                assert_eq!(output, expected);
                            }
                        }
                        blocks += 1;
                    }
                    key.clear();
                    expanded.clear();
                    assert_eq!(storage, [0; $k]);
                    assert_eq!(schedule, [0; $s]);
                }
                assert_eq!(blocks, 110);
                println!(concat!(
                    "AESAVS_MMT: ",
                    $bits,
                    " 20 records; 110 blocks; 2 owners; public encryption checked"
                ));
                Ok(())
            }

            #[test]
            fn malformed_vectors_fail() {
                for (text, mct) in [(MCT, true), (MMT, false)] {
                    for bad in [
                        String::new(),
                        text.replace("[DECRYPT]", "[ENCRYPT]"),
                        text.replacen("COUNT = 0", "COUNT = 1", 1),
                        text.replacen("KEY = ", "KEY = z", 1),
                        text.replacen("KEY = ", "KEY = 00", 1),
                        text.replacen("KEY = ", "OTHER = ", 1),
                        text.replacen("PLAINTEXT = ", "PLAINTEXT = 00", 1),
                        text.replacen("CIPHERTEXT = ", "CIPHERTEXT = z", 1),
                        format!("{text}\nCOUNT = 0\n"),
                        format!("{text}\n{text}"),
                    ] {
                        assert!(records::<$k>(&bad, mct).is_err());
                    }
                    // Every mandatory line matters, not only the first record.
                    let lines: Vec<_> = text.lines().collect();
                    for (i, line) in lines.iter().enumerate() {
                        if line.is_empty() || line.starts_with('#') {
                            continue;
                        }
                        let missing = lines
                            .iter()
                            .enumerate()
                            .filter_map(|(j, line)| (i != j).then_some(*line))
                            .collect::<Vec<_>>()
                            .join("\n");
                        assert!(records::<$k>(&missing, mct).is_err(), "missing line {i}");
                    }
                    assert!(records::<$k>(text, !mct).is_err());
                }
            }
        }
    };
}

width!(aes128, Aes128Key, Aes128ExpandedKey, 16, 176, "128");
width!(aes192, Aes192Key, Aes192ExpandedKey, 24, 208, "192");
width!(aes256, Aes256Key, Aes256ExpandedKey, 32, 240, "256");

#[test]
fn key_updates_use_the_correct_tail() -> Check<()> {
    let previous = core::array::from_fn(|i| i as u8);
    let last = core::array::from_fn(|i| (16 + i) as u8);
    assert_eq!(
        next_key(&[0xa5; 16], &previous, &last)?,
        core::array::from_fn(|i| 0xa5 ^ (16 + i) as u8)
    );
    assert_eq!(
        next_key(&[0xa5; 24], &previous, &last)?,
        core::array::from_fn(|i| 0xa5 ^ (8 + i) as u8)
    );
    assert_eq!(
        next_key(&[0xa5; 32], &previous, &last)?,
        core::array::from_fn(|i| 0xa5 ^ i as u8)
    );
    assert!(next_key(&[0; 20], &previous, &last).is_err());
    Ok(())
}

#[test]
fn iteration_count_and_penultimate_output_are_exact() -> Check<()> {
    let mut calls = 0usize;
    let (previous, last) = iterate([0; 16], |input| {
        assert_eq!(*input, [calls as u8; 16]);
        calls += 1;
        Ok([calls as u8; 16])
    })?;
    assert_eq!(calls, 1000);
    assert_eq!(previous, [999u16 as u8; 16]);
    assert_eq!(last, [1000u16 as u8; 16]);
    Ok(())
}

#[test]
fn campaign_rejects_wrong_outputs_keys_inputs_and_directions() -> Check<()> {
    let text = include_str!("fixtures/ECBMCT128.rsp");
    assert!(campaign(&[], |_: &[u8; 16], _, _| Ok(([0; 16], [0; 16]))).is_err());
    // Fake the first expected output but a wrong penultimate value: AES-128's
    // next key uses only the final block. Mutating record 1 must still fail.
    for mutation in 0..4 {
        let mut data = records::<16>(text, true)?;
        match mutation {
            0 => data[0].expected[0] ^= 1,
            1 => data[1].key[0] ^= 1,
            2 => data[1].input[0] ^= 1,
            _ => data[0].inverse = true,
        }
        let original = records::<16>(text, true)?;
        let mut calls = 0;
        let result = campaign(&data, |_, _, _| {
            let last = original[calls].expected.as_slice().try_into()?;
            calls += 1;
            Ok(([0; 16], last))
        });
        assert!(result.is_err());
        assert!(calls <= 1);
    }
    Ok(())
}
