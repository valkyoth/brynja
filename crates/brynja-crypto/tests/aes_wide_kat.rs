//! Complete AES-192/256 single-block AESAVS KAT files, not CAVP validation.
use brynja_crypto::aes::*;

struct Vector<const K: usize> {
    decrypt: bool,
    key: [u8; K],
    input: [u8; 16],
    expected: [u8; 16],
}

fn hex<const N: usize>(text: &str) -> Result<[u8; N], Error> {
    if Some(text.len()) != N.checked_mul(2) || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::SecretMemory);
    }
    let mut output = [0; N];
    for (byte, pair) in output.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        *byte = core::str::from_utf8(pair)
            .ok()
            .and_then(|s| u8::from_str_radix(s, 16).ok())
            .ok_or(Error::SecretMemory)?;
    }
    Ok(output)
}

fn field<const N: usize>(line: Option<&str>, prefix: &str) -> Result<[u8; N], Error> {
    hex(line
        .and_then(|s| s.strip_prefix(prefix))
        .ok_or(Error::SecretMemory)?)
}

// Every section, field, count and width is mandatory. No skipped malformed
// records or inferred population, even when the file remains parseable.
fn vectors<const K: usize>(text: &str, count: usize) -> Result<Vec<Vector<K>>, Error> {
    if count == 0 {
        return Err(Error::SecretMemory);
    }
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with('#'));
    let mut result = Vec::new();
    for (section, decrypt, input, output) in [
        ("[ENCRYPT]", false, "PLAINTEXT = ", "CIPHERTEXT = "),
        ("[DECRYPT]", true, "CIPHERTEXT = ", "PLAINTEXT = "),
    ] {
        if lines.next() != Some(section) {
            return Err(Error::SecretMemory);
        }
        for index in 0..count {
            if lines.next() != Some(format!("COUNT = {index}").as_str()) {
                return Err(Error::SecretMemory);
            }
            result.push(Vector {
                decrypt,
                key: field(lines.next(), "KEY = ")?,
                input: field(lines.next(), input)?,
                expected: field(lines.next(), output)?,
            });
        }
    }
    if lines.next().is_some() {
        return Err(Error::SecretMemory);
    }
    Ok(result)
}

macro_rules! corpus {
    ($module:ident, $key:ident, $cached:ident, $k:literal, $s:literal, $bits:literal,
     $gfs:literal, $sbox:literal, $varkey:literal, $total:literal) => {
        mod $module {
            use super::*;
            const FILES: [(&str, &str, usize); 4] = [
                (
                    "GFSbox",
                    include_str!(concat!("fixtures/aes", $bits, "/ECBGFSbox", $bits, ".rsp")),
                    $gfs,
                ),
                (
                    "KeySbox",
                    include_str!(concat!("fixtures/aes", $bits, "/ECBKeySbox", $bits, ".rsp")),
                    $sbox,
                ),
                (
                    "VarKey",
                    include_str!(concat!("fixtures/aes", $bits, "/ECBVarKey", $bits, ".rsp")),
                    $varkey,
                ),
                (
                    "VarTxt",
                    include_str!(concat!("fixtures/aes", $bits, "/ECBVarTxt", $bits, ".rsp")),
                    128,
                ),
            ];

            #[test]
            fn all_four_kat_files_both_owners() -> Result<(), Error> {
                let mut total = 0usize;
                for (name, text, count) in FILES {
                    for (case, vector) in vectors::<$k>(text, count)?.iter().enumerate() {
                        let mut storage = [0xa5; $k];
                        let mut expanded = [0xa5; $s];
                        let key = $key::new(&vector.key, &mut storage)?;
                        let cached = $cached::new(&vector.key, &mut expanded)?;
                        let mut output = [0xa5; 16];
                        for cache in [false, true] {
                            let result = match (cache, vector.decrypt) {
                                (false, false) => key.encrypt_block(&vector.input, &mut output),
                                (false, true) => key.decrypt_block(&vector.input, &mut output),
                                (true, false) => cached.encrypt_block(&vector.input, &mut output),
                                (true, true) => cached.decrypt_block(&vector.input, &mut output),
                            }?;
                            assert_eq!(
                                result.expose(),
                                vector.expected,
                                "{name} case {case}, cached={cache}"
                            );
                            result.clear();
                            assert_eq!(output, [0; 16]);
                            if !vector.decrypt {
                                if cache {
                                    cached.encrypt_block_public(
                                        &vector.input,
                                        &mut output,
                                        PublicCiphertext::acknowledge(),
                                    )?;
                                } else {
                                    key.encrypt_block_public(
                                        &vector.input,
                                        &mut output,
                                        PublicCiphertext::acknowledge(),
                                    )?;
                                }
                                assert_eq!(
                                    output, vector.expected,
                                    "public {name} case {case}, cached={cache}"
                                );
                            }
                        }
                        key.clear();
                        cached.clear();
                        assert_eq!(storage, [0; $k]);
                        assert_eq!(expanded, [0; $s]);
                        total = total.checked_add(1).ok_or(Error::SecretMemory)?;
                    }
                }
                assert_eq!(total, $total);
                println!(concat!("AES", $bits, "_KAT_RECORDS: ", $total));
                Ok(())
            }

            #[test]
            fn parser_rejects_missing_extra_or_malformed_data() {
                for (_, text, count) in FILES {
                    for malformed in [
                        String::new(),
                        text.replace("[DECRYPT]", "[ENCRYPT]"),
                        text.replacen("COUNT = 0", "COUNT = 1", 1),
                        text.replacen("KEY = ", "UNKNOWN = ", 1),
                        text.replacen("KEY = ", "KEY = z", 1),
                        text.replacen("KEY = ", "KEY = 00", 1),
                        text.replacen("PLAINTEXT = ", "PLAINTEXT = 00", 1),
                        text.replacen("CIPHERTEXT = ", "CIPHERTEXT = z", 1),
                        format!("{text}\nCOUNT = 0\n"),
                    ] {
                        assert!(vectors::<$k>(&malformed, count).is_err());
                    }
                    assert!(vectors::<$k>(text, count.saturating_sub(1)).is_err());
                    assert!(vectors::<$k>(text, count.saturating_add(1)).is_err());
                    assert!(vectors::<$k>(text, 0).is_err());
                }
                // Exhaustive line deletion on the small GFSbox file.
                let (_, text, count) = FILES[0];
                for (index, line) in text.lines().enumerate() {
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    let truncated = text
                        .lines()
                        .enumerate()
                        .filter_map(|(i, s)| (i != index).then_some(s))
                        .collect::<Vec<_>>()
                        .join("\n");
                    assert!(
                        vectors::<$k>(&truncated, count).is_err(),
                        "removed line {index}"
                    );
                }
            }
        }
    };
}

corpus!(
    aes192,
    Aes192Key,
    Aes192ExpandedKey,
    24,
    208,
    "192",
    6,
    24,
    192,
    700
);
corpus!(
    aes256,
    Aes256Key,
    Aes256ExpandedKey,
    32,
    240,
    "256",
    5,
    16,
    256,
    810
);
