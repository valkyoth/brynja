//! Explicit opt-in independent OpenSSL comparison, using public synthetic data.
//! Not a production dependency, mode API, timing test or CAVP validation.
#![forbid(unsafe_code)]

use brynja_aes_public_api_fixture::aes::*;
use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

// The registered runner selects and hashes the executable before starting Cargo.
// Direct ignored runs must explicitly select the same trusted local oracle.
fn oracle_executable(value: Option<std::ffi::OsString>) -> TestResult<PathBuf> {
    let path =
        PathBuf::from(value.ok_or("BRYNJA_OPENSSL must select an absolute OpenSSL executable")?);
    if !path.is_absolute() || !path.is_file() {
        return Err("OpenSSL executable must be an absolute regular file".into());
    }
    Ok(path.canonicalize()?)
}

#[test]
fn oracle_path_admission() -> TestResult<()> {
    assert!(oracle_executable(None).is_err());
    assert!(oracle_executable(Some("openssl".into())).is_err());
    assert!(oracle_executable(Some(std::env::temp_dir().into_os_string())).is_err());
    let executable = std::env::current_exe()?;
    assert_eq!(
        oracle_executable(Some(executable.clone().into_os_string()))?,
        executable.canonicalize()?
    );
    Ok(())
}

fn oracle(executable: &Path, key: &[u8], input: &[u8], decrypt: bool) -> TestResult<Vec<u8>> {
    let cipher = match key.len() {
        16 => "-aes-128-ecb",
        24 => "-aes-192-ecb",
        32 => "-aes-256-ecb",
        _ => return Err("invalid oracle key width".into()),
    };
    let key = key
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    // These command-line keys are public test material only. Never use this
    // adapter with application secrets. No shell or user-selected arguments.
    let mut child = Command::new(executable)
        .args([
            "enc",
            cipher,
            "-nopad",
            "-nosalt",
            "-K",
            &key,
            if decrypt { "-d" } else { "-e" },
        ])
        .env("OPENSSL_CONF", "/dev/null")
        .env_remove("OPENSSL_MODULES")
        .env_remove("OPENSSL_ENGINES")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("missing OpenSSL stdin")?
        .write_all(input)?;
    let result = child.wait_with_output()?;
    if !result.status.success() {
        return Err(format!(
            "OpenSSL failed: {}",
            String::from_utf8_lossy(&result.stderr)
        )
        .into());
    }
    if result.stdout.len() != input.len() {
        return Err("wrong OpenSSL output length".into());
    }
    Ok(result.stdout)
}

fn fill(state: &mut u64, bytes: &mut [u8]) {
    // Fixed reproducible public corpus, not a cryptographic random generator.
    for byte in bytes {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *byte = state.to_le_bytes().first().copied().unwrap_or(0);
    }
}

macro_rules! corpus {
($test:ident, $key:ident, $cached:ident, $k:literal, $s:literal, $bits:literal, $seed:literal) => {
#[test]
#[ignore = "requires independent openssl executable; run the explicit packaged differential registration"]
fn $test() -> TestResult<()> {
    let executable = oracle_executable(std::env::var_os("BRYNJA_OPENSSL"))?;
    let version = Command::new(&executable).arg("version").output()?;
    if !version.status.success() {
        return Err("OpenSSL version probe failed".into());
    }
    println!(
        "Independent oracle: {}",
        String::from_utf8_lossy(&version.stdout).trim()
    );
    let mut random = $seed;
    let mut comparisons = 0usize;
    for case in 0..64 {
        let mut key_bytes = [0; $k];
        fill(&mut random, &mut key_bytes);
        if case == 0 {
            key_bytes.fill(0);
        }
        if case == 1 {
            key_bytes.fill(255);
        }
        let mut storage = [0; $k];
        let key = $key::new(&key_bytes, &mut storage).map_err(|_| "key admission")?;
        let mut expanded = [0; $s];
        let cached = $cached::new(&key_bytes, &mut expanded)
            .map_err(|_| "cached key admission")?;
        for decrypt in [false, true] {
            let mut input = [0; 512];
            fill(&mut random, &mut input);
            input[..16].fill(0);
            input[16..32].fill(255);
            // Independent random ciphertext for inverse testing, not output
            // produced by the implementation under test or just round trips.
            let expected = oracle(&executable, &key_bytes, &input, decrypt)?;
            for (block, expected) in input
                .as_chunks::<16>()
                .0
                .iter()
                .zip(expected.as_chunks::<16>().0)
            {
                let mut output = [0; 16];
                if decrypt {
                    let result = key
                        .decrypt_block(block, &mut output)
                        .map_err(|_| "decrypt")?;
                    assert_eq!(result.expose(), expected, "inverse corpus {case}");
                } else {
                    assert_eq!(key.encrypt_block(block, &mut output).map_err(|_| "secret encrypt")?.expose(), expected);
                    assert_eq!(output, [0; 16]);
                    key.encrypt_block_public(block, &mut output, PublicCiphertext::acknowledge())
                        .map_err(|_| "encrypt")?;
                    assert_eq!(&output, expected, "forward corpus {case}");
                }
                if decrypt { assert_eq!(output, [0; 16]); }
                comparisons = comparisons.checked_add(1).ok_or("comparison overflow")?;
                if decrypt {
                    assert_eq!(
                        cached
                            .decrypt_block(block, &mut output)
                            .map_err(|_| "cached decrypt")?
                            .expose(),
                        expected,
                        "cached inverse {case}"
                    );
                } else {
                    assert_eq!(cached.encrypt_block(block, &mut output).map_err(|_| "cached secret encrypt")?.expose(), expected);
                    assert_eq!(output, [0; 16]);
                    cached
                        .encrypt_block_public(block, &mut output, PublicCiphertext::acknowledge())
                        .map_err(|_| "cached encrypt")?;
                    assert_eq!(&output, expected, "cached forward {case}");
                }
                if decrypt { assert_eq!(output, [0; 16]); }
            }
        }
        key.clear();
        cached.clear();
        assert_eq!(storage, [0; $k]);
        assert_eq!(expanded, [0; $s]);
    }
    assert_eq!(comparisons, 4096);
    println!(concat!("AES", $bits, "_OPENSSL_COMPARISONS: 4096"));
    println!(concat!("AES", $bits, "_CACHED_OPENSSL_COMPARISONS: 4096"));
    println!(concat!("AES", $bits, "_PUBLIC_OPENSSL_COMPARISONS: 2048 per owner"));
    Ok(())
}
};
}

corpus!(
    aes128_openssl_independent_corpus,
    Aes128Key,
    Aes128ExpandedKey,
    16,
    176,
    "128",
    0x51de_cafe_2730_0001u64
);

corpus!(
    aes192_openssl_independent_corpus,
    Aes192Key,
    Aes192ExpandedKey,
    24,
    208,
    "192",
    0x51de_cafe_2731_0192u64
);
corpus!(
    aes256_openssl_independent_corpus,
    Aes256Key,
    Aes256ExpandedKey,
    32,
    240,
    "256",
    0x51de_cafe_2731_0256u64
);
