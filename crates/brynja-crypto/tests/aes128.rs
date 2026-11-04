//! Public AES-128 development regressions. Fixed answers, not only round trips.
use brynja_crypto::aes::{Aes128ExpandedKey, Aes128Key, Error, PublicCiphertext};

const GFSBOX: &str = include_str!("fixtures/aes128/ECBGFSbox128.rsp");
const KEYSBOX: &str = include_str!("fixtures/aes128/ECBKeySbox128.rsp");
const VARKEY: &str = include_str!("fixtures/aes128/ECBVarKey128.rsp");
const VARTXT: &str = include_str!("fixtures/aes128/ECBVarTxt128.rsp");

struct Vector {
    decrypt: bool,
    key: [u8; 16],
    input: [u8; 16],
    expected: [u8; 16],
}

// Fail closed on missing/extra sections, records, fields, counts and malformed
// hex. The caller supplies an independently fixed population for each file.
fn vectors(text: &str, per_direction: usize) -> Result<Vec<Vector>, Error> {
    if per_direction == 0 {
        return Err(Error::SecretMemory);
    }
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'));
    let mut result = Vec::new();
    for (section, decrypt, input_name, output_name) in [
        ("[ENCRYPT]", false, "PLAINTEXT = ", "CIPHERTEXT = "),
        ("[DECRYPT]", true, "CIPHERTEXT = ", "PLAINTEXT = "),
    ] {
        if lines.next() != Some(section) {
            return Err(Error::SecretMemory);
        }
        for count in 0..per_direction {
            if lines.next() != Some(format!("COUNT = {count}").as_str()) {
                return Err(Error::SecretMemory);
            }
            let mut field = |prefix| {
                hex(lines
                    .next()
                    .and_then(|line| line.strip_prefix(prefix))
                    .ok_or(Error::SecretMemory)?)
            };
            result.push(Vector {
                decrypt,
                key: field("KEY = ")?,
                input: field(input_name)?,
                expected: field(output_name)?,
            });
        }
    }
    if lines.next().is_some() {
        return Err(Error::SecretMemory);
    }
    Ok(result)
}

#[test]
fn nist_aesavs_all_four_aes128_ecb_kat_files() -> Result<(), Error> {
    let mut total = 0usize;
    for (name, text, count) in [
        ("GFSbox", GFSBOX, 7),
        ("KeySbox", KEYSBOX, 21),
        ("VarKey", VARKEY, 128),
        ("VarTxt", VARTXT, 128),
    ] {
        for (case, vector) in vectors(text, count)?.iter().enumerate() {
            let mut storage = [0; 16];
            let key = Aes128Key::new(&vector.key, &mut storage)?;
            let mut output = [0xa5; 16];
            let block = if vector.decrypt {
                key.decrypt_block(&vector.input, &mut output)?
            } else {
                key.encrypt_block(&vector.input, &mut output)?
            };
            assert_eq!(block.expose(), vector.expected, "{name} case {case}");
            block.clear();
            assert_eq!(output, [0; 16]);
            if !vector.decrypt {
                key.encrypt_block_public(
                    &vector.input,
                    &mut output,
                    PublicCiphertext::acknowledge(),
                )?;
                assert_eq!(output, vector.expected, "public {name} case {case}");
            }
            key.clear();
            assert_eq!(storage, [0; 16]);
            let mut expanded_storage = [0xa5; 176];
            let cached = Aes128ExpandedKey::new(&vector.key, &mut expanded_storage)?;
            let result = if vector.decrypt {
                cached.decrypt_block(&vector.input, &mut output)?
            } else {
                cached.encrypt_block(&vector.input, &mut output)?
            };
            assert_eq!(
                result.expose(),
                vector.expected,
                "cached {name} case {case}"
            );
            result.clear();
            if !vector.decrypt {
                cached.encrypt_block_public(
                    &vector.input,
                    &mut output,
                    PublicCiphertext::acknowledge(),
                )?;
                assert_eq!(output, vector.expected, "cached public {name} case {case}");
            }
            cached.clear();
            assert_eq!(expanded_storage, [0; 176]);
            total = total.checked_add(1).ok_or(Error::SecretMemory)?;
        }
    }
    assert_eq!(total, 568);
    Ok(())
}

#[test]
fn nist_vector_parser_rejects_incomplete_or_malformed_populations() {
    for malformed in [
        String::new(),
        GFSBOX.replace("[DECRYPT]", "[ENCRYPT]"),
        GFSBOX.replacen("COUNT = 0", "COUNT = 1", 1),
        GFSBOX.replacen("KEY = ", "UNKNOWN = ", 1),
        GFSBOX.replacen("00000000000000000000000000000000", "zz", 1),
        GFSBOX.replacen("COUNT = 1", "COUNT = 0", 1),
        format!("{GFSBOX}\nCOUNT = 7\n"),
    ] {
        assert!(vectors(&malformed, 7).is_err());
    }
    assert!(vectors(GFSBOX, 6).is_err());
    assert!(vectors(GFSBOX, 8).is_err());
    assert!(vectors(GFSBOX, 0).is_err());
    // Removing any data line must invalidate the complete file, not silently
    // reduce the test population. Comments and blank lines are non-semantic.
    for (index, line) in GFSBOX.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let truncated = GFSBOX
            .lines()
            .enumerate()
            .filter_map(|(i, l)| (i != index).then_some(l))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(vectors(&truncated, 7).is_err(), "removed line {index}");
    }
}

#[test]
fn public_ciphertext_commit_preserves_inputs_and_canaries() -> Result<(), Error> {
    let input = [0; 16];
    let mut storage = [0; 16];
    let key = Aes128Key::new(&input, &mut storage)?;
    let mut output = [0xa5; 18];
    let block: &mut [u8; 16] = output
        .get_mut(1..17)
        .ok_or(Error::SecretMemory)?
        .try_into()
        .map_err(|_| Error::SecretMemory)?;
    key.encrypt_block_public(&input, block, PublicCiphertext::acknowledge())?;
    key.clear();
    assert_eq!(
        output.get(1..17),
        Some(hex("66e94bd4ef8a2c3b884cfa59ca342b2e")?.as_slice())
    );
    assert_eq!(output.first(), Some(&0xa5));
    assert_eq!(output.last(), Some(&0xa5));
    assert_eq!(input, [0; 16]);
    assert_eq!(storage, [0; 16]);
    let mut expanded = [0xa5; 176];
    let cached = Aes128ExpandedKey::new(&input, &mut expanded)?;
    let expected = output;
    let block: &mut [u8; 16] = output
        .get_mut(1..17)
        .ok_or(Error::SecretMemory)?
        .try_into()
        .map_err(|_| Error::SecretMemory)?;
    cached.encrypt_block_public(&input, block, PublicCiphertext::acknowledge())?;
    cached.clear();
    assert_eq!(output, expected);
    assert_eq!(expanded, [0; 176]);
    Ok(())
}

fn hex(text: &str) -> Result<[u8; 16], Error> {
    if text.len() != 32 {
        return Err(Error::SecretMemory);
    }
    let mut bytes = [0; 16];
    for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        *byte = u8::from_str_radix(
            core::str::from_utf8(pair).map_err(|_| Error::SecretMemory)?,
            16,
        )
        .map_err(|_| Error::SecretMemory)?;
    }
    Ok(bytes)
}

#[test]
fn fips197_and_sp80038a_block_answers_both_directions() -> Result<(), Error> {
    // FIPS 197 Appendix B / original Appendix C.1; SP 800-38A F.1.1.
    // The latter's individual blocks are used as primitive vectors, not a mode API.
    for (key, plaintext, ciphertext) in [
        (
            "000102030405060708090a0b0c0d0e0f",
            "00112233445566778899aabbccddeeff",
            "69c4e0d86a7b0430d8cdb78070b4c55a",
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            "3243f6a8885a308d313198a2e0370734",
            "3925841d02dc09fbdc118597196a0b32",
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            "6bc1bee22e409f96e93d7e117393172a",
            "3ad77bb40d7a3660a89ecaf32466ef97",
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "f5d3d58503b9699de785895a96fdbaaf",
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "43b1cd7f598ece23881b00e3ed030688",
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            "f69f2445df4f9b17ad2b417be66c3710",
            "7b0c785e27e8ad3f8223207104725dd4",
        ),
    ] {
        let mut storage = [0; 16];
        let key = Aes128Key::new(&hex(key)?, &mut storage)?;
        let mut output = [0xa5; 16];
        let plaintext = hex(plaintext)?;
        let ciphertext = hex(ciphertext)?;
        {
            let result = key.encrypt_block(&plaintext, &mut output)?;
            assert_eq!(result.expose(), ciphertext);
        }
        assert_eq!(output, [0; 16]);
        {
            let result = key.decrypt_block(&ciphertext, &mut output)?;
            assert_eq!(result.expose(), plaintext);
        }
        assert_eq!(output, [0; 16]);
        drop(key);
        assert_eq!(storage, [0; 16]);
    }
    Ok(())
}

#[test]
fn output_outlives_key_and_explicit_clear_preserves_canaries() -> Result<(), Error> {
    let mut key_bytes = [0x42; 18];
    let mut output_bytes = [0xa5; 18];
    let result = {
        let storage: &mut [u8; 16] = key_bytes
            .get_mut(1..17)
            .ok_or(Error::SecretMemory)?
            .try_into()
            .map_err(|_| Error::SecretMemory)?;
        let output: &mut [u8; 16] = output_bytes
            .get_mut(1..17)
            .ok_or(Error::SecretMemory)?
            .try_into()
            .map_err(|_| Error::SecretMemory)?;
        let key = Aes128Key::new(&[0; 16], storage)?;
        let result = key.encrypt_block(&[0; 16], output)?;
        key.clear();
        result
    };
    assert_eq!(result.expose(), hex("66e94bd4ef8a2c3b884cfa59ca342b2e")?);
    result.clear();
    assert_eq!(key_bytes.first(), Some(&0x42));
    assert_eq!(key_bytes.last(), Some(&0x42));
    assert_eq!(key_bytes.get(1..17), Some([0; 16].as_slice()));
    assert_eq!(output_bytes.first(), Some(&0xa5));
    assert_eq!(output_bytes.last(), Some(&0xa5));
    assert_eq!(output_bytes.get(1..17), Some([0; 16].as_slice()));
    let mut expanded = [[0xa5; 176]; 3];
    let mut out = [[0x5a; 16]; 3];
    let result = {
        let key = Aes128ExpandedKey::new(&[0; 16], &mut expanded[1])?;
        let result = key.encrypt_block(&[0; 16], &mut out[1])?;
        key.clear();
        result
    };
    assert_eq!(result.expose(), hex("66e94bd4ef8a2c3b884cfa59ca342b2e")?);
    result.clear();
    assert_eq!(expanded, [[0xa5; 176], [0; 176], [0xa5; 176]]);
    assert_eq!(out, [[0x5a; 16], [0; 16], [0x5a; 16]]);
    Ok(())
}

#[test]
fn independent_key_owners_can_be_reused_without_export() -> Result<(), Error> {
    for seed in 0..=u8::MAX {
        let mut key_storage = [0; 16];
        let key = Aes128Key::new(&[seed; 16], &mut key_storage)?;
        let input = [seed ^ 0x59; 16];
        let mut encrypted = [0; 16];
        let ciphertext = key.encrypt_block(&input, &mut encrypted)?;
        let ciphertext: &[u8; 16] = ciphertext
            .expose()
            .try_into()
            .map_err(|_| Error::SecretMemory)?;
        let mut decrypted = [0; 16];
        let result = key.decrypt_block(ciphertext, &mut decrypted)?;
        assert_eq!(result.expose(), input);
        let mut expanded = [0; 176];
        let cached = Aes128ExpandedKey::new(&[seed; 16], &mut expanded)?;
        let mut cached_output = [0; 16];
        assert_eq!(
            cached.encrypt_block(&input, &mut cached_output)?.expose(),
            ciphertext
        );
        assert_eq!(
            cached
                .decrypt_block(ciphertext, &mut cached_output)?
                .expose(),
            input
        );
    }
    Ok(())
}
