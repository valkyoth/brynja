//! Workspace-only candidate-kernel tests. Not a production key expansion API.
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(aes_expansion_candidate)]
mod expansion;

#[cfg(target_arch = "x86_64")]
#[path = "../../crates/brynja-crypto-cpu/src/aes/x86.rs"]
mod kernel;
#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
#[path = "../../crates/brynja-crypto-cpu/src/aes/aarch64.rs"]
mod kernel;

fn available() -> bool {
    #[cfg(target_arch = "x86_64")]
    return std::is_x86_feature_detected!("aes") && std::is_x86_feature_detected!("sse2");
    #[cfg(target_arch = "aarch64")]
    return std::arch::is_aarch64_feature_detected!("aes")
        && std::arch::is_aarch64_feature_detected!("neon");
}

fn transform<const N: usize>(state: &mut [u8; 16], schedule: &[[u8; 16]; N], inverse: bool) {
    // Absence fails the campaign; it must never look like a skipped backend PASS.
    assert!(
        available(),
        "candidate AES ISA unavailable: no kernel executed"
    );
    // SAFETY: Runtime checks above cover the exact ISA bundle. This harness
    // requires stable CPU features throughout execution (including migration).
    // Schedule/blocks are test data and all buffers have their exact typed size.
    unsafe { kernel::transform(state, schedule, inverse) }
}

// Independent, test-only FIPS 197 key expansion. Deliberately not exported or
// used for production: no secret owner, clearing guarantee or timing claim.
fn multiply(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0;
    for _ in 0..8 {
        if b & 1 != 0 {
            product ^= a;
        }
        a = (a << 1) ^ if a & 128 != 0 { 0x1b } else { 0 };
        b >>= 1;
    }
    product
}

fn sbox(value: u8) -> u8 {
    let mut inverse = 1;
    for _ in 0..254 {
        inverse = multiply(inverse, value);
    }
    inverse
        ^ inverse.rotate_left(1)
        ^ inverse.rotate_left(2)
        ^ inverse.rotate_left(3)
        ^ inverse.rotate_left(4)
        ^ 0x63
}

fn expand<const N: usize>(key: &[u8]) -> [[u8; 16]; N] {
    assert!(matches!((key.len(), N), (16, 11) | (24, 13) | (32, 15)));
    let mut bytes = vec![0; N * 16];
    bytes[..key.len()].copy_from_slice(key);
    let mut rcon = 1;
    for offset in (key.len()..bytes.len()).step_by(4) {
        let mut word: [u8; 4] = bytes[offset - 4..offset].try_into().unwrap();
        if offset % key.len() == 0 {
            word.rotate_left(1);
            word = word.map(sbox);
            word[0] ^= rcon;
            rcon = multiply(rcon, 2);
        } else if key.len() == 32 && offset % 32 == 16 {
            word = word.map(sbox);
        }
        for i in 0..4 {
            bytes[offset + i] = bytes[offset + i - key.len()] ^ word[i];
        }
    }
    bytes.as_chunks::<16>().0.try_into().unwrap()
}

struct Vector<const K: usize> {
    inverse: bool,
    key: [u8; K],
    input: [u8; 16],
    expected: [u8; 16],
}

fn field<const N: usize>(line: Option<&str>, prefix: &str) -> Result<[u8; N], &'static str> {
    let text = line
        .and_then(|s| s.strip_prefix(prefix))
        .ok_or("missing field")?;
    if text.len() != N * 2 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid hex field");
    }
    let mut output = [0; N];
    for (byte, pair) in output.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| "utf8")?, 16)
            .map_err(|_| "hex")?;
    }
    Ok(output)
}

fn vectors<const K: usize>(text: &str, count: usize) -> Result<Vec<Vector<K>>, &'static str> {
    if count == 0 {
        return Err("empty corpus");
    }
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with('#'));
    let mut records = Vec::new();
    for (section, inverse, input, output) in [
        ("[ENCRYPT]", false, "PLAINTEXT = ", "CIPHERTEXT = "),
        ("[DECRYPT]", true, "CIPHERTEXT = ", "PLAINTEXT = "),
    ] {
        if lines.next() != Some(section) {
            return Err("section");
        }
        for i in 0..count {
            if lines.next() != Some(format!("COUNT = {i}").as_str()) {
                return Err("count");
            }
            records.push(Vector {
                inverse,
                key: field(lines.next(), "KEY = ")?,
                input: field(lines.next(), input)?,
                expected: field(lines.next(), output)?,
            });
        }
    }
    if lines.next().is_some() {
        return Err("trailing data");
    }
    Ok(records)
}

macro_rules! corpus {
    ($test:ident, $bits:literal, $k:literal, $n:literal, $gfs:literal, $sbox:literal, $total:literal) => {
        #[test]
        fn $test() {
            assert!(available(), "required AES ISA absent");
            let mut total = 0;
            for (text, count) in [
                (
                    include_str!(concat!(
                        "../../crates/brynja-crypto/tests/fixtures/aes",
                        $bits,
                        "/ECBGFSbox",
                        $bits,
                        ".rsp"
                    )),
                    $gfs,
                ),
                (
                    include_str!(concat!(
                        "../../crates/brynja-crypto/tests/fixtures/aes",
                        $bits,
                        "/ECBKeySbox",
                        $bits,
                        ".rsp"
                    )),
                    $sbox,
                ),
                (
                    include_str!(concat!(
                        "../../crates/brynja-crypto/tests/fixtures/aes",
                        $bits,
                        "/ECBVarKey",
                        $bits,
                        ".rsp"
                    )),
                    $bits,
                ),
                (
                    include_str!(concat!(
                        "../../crates/brynja-crypto/tests/fixtures/aes",
                        $bits,
                        "/ECBVarTxt",
                        $bits,
                        ".rsp"
                    )),
                    128,
                ),
            ] {
                for vector in vectors::<$k>(text, count).unwrap() {
                    let schedule = expand::<$n>(&vector.key);
                    let original = schedule;
                    let mut block = vector.input;
                    transform(&mut block, &schedule, vector.inverse);
                    assert_eq!(
                        block, vector.expected,
                        "KAT record {total}, inverse={}",
                        vector.inverse
                    );
                    assert_eq!(schedule, original, "kernel modified forward schedule");
                    // Repeat the opposite direction without re-expansion.
                    transform(&mut block, &schedule, !vector.inverse);
                    assert_eq!(block, vector.input);
                    total += 1;
                }
            }
            assert_eq!(total, $total);
            println!("\nAES_KERNEL_KAT_PASS: {}:{}", $bits, total);
        }
    };
}
corpus!(aes128_kat, 128, 16, 11, 7, 21, 568);
corpus!(aes192_kat, 192, 24, 13, 6, 24, 700);
corpus!(aes256_kat, 256, 32, 15, 5, 16, 810);

fn alignment<const N: usize>(key: &[u8]) {
    let schedule = expand::<N>(key);
    let mut expected = [0x5a; 16];
    transform(&mut expected, &schedule, false);
    for state_offset in 0..16 {
        for schedule_offset in 0..16 {
            let mut state_bytes = [0xa5; 48];
            state_bytes[state_offset..state_offset + 16].fill(0x5a);
            let mut key_bytes = vec![0xa5; N * 16 + 32];
            for (source, destination) in schedule
                .iter()
                .zip(key_bytes[schedule_offset..schedule_offset + N * 16].chunks_exact_mut(16))
            {
                destination.copy_from_slice(source);
            }
            let before = key_bytes.clone();
            let unaligned: &[[u8; 16]; N] = key_bytes[schedule_offset..schedule_offset + N * 16]
                .as_chunks::<16>()
                .0
                .try_into()
                .unwrap();
            let block: &mut [u8; 16] = (&mut state_bytes[state_offset..state_offset + 16])
                .try_into()
                .unwrap();
            transform(block, unaligned, false);
            assert_eq!(*block, expected);
            transform(block, unaligned, true);
            assert_eq!(*block, [0x5a; 16]);
            assert!(state_bytes[..state_offset].iter().all(|b| *b == 0xa5));
            assert!(state_bytes[state_offset + 16..].iter().all(|b| *b == 0xa5));
            assert_eq!(key_bytes, before);
        }
    }
}

#[test]
fn every_byte_alignment_and_canaries() {
    alignment::<11>(&[0x42; 16]);
    alignment::<13>(&[0x42; 24]);
    alignment::<15>(&[0x42; 32]);
    println!("\nAES_KERNEL_ALIGNMENT_PASS: 768");
}

#[test]
fn parser_rejects_incomplete_or_substituted_vectors() {
    let text = include_str!("../../crates/brynja-crypto/tests/fixtures/aes128/ECBGFSbox128.rsp");
    for bad in [
        String::new(),
        text.replace("[DECRYPT]", "[ENCRYPT]"),
        text.replacen("COUNT = 0", "COUNT = 1", 1),
        text.replacen("KEY = ", "KEY = z", 1),
        text.replacen("PLAINTEXT = ", "PLAINTEXT = 00", 1),
        format!("{text}\nextra"),
    ] {
        assert!(vectors::<16>(&bad, 7).is_err());
    }
    for count in [0, 6, 8] {
        assert!(vectors::<16>(text, count).is_err());
    }
    assert!(vectors::<24>(text, 7).is_err());
}
