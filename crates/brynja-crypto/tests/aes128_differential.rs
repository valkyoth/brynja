//! Explicit opt-in independent OpenSSL comparison, using public synthetic data.
//! Not a production dependency, mode API, timing test or CAVP validation.
use brynja_crypto::aes::{Aes128ExpandedKey, Aes128Key, PublicCiphertext};
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

fn oracle(executable: &Path, key: &[u8; 16], input: &[u8], decrypt: bool) -> TestResult<Vec<u8>> {
    let key = key
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    // These command-line keys are public test material only. Never use this
    // adapter with application secrets. No shell or user-selected arguments.
    let mut child = Command::new(executable)
        .args([
            "enc",
            "-aes-128-ecb",
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

#[test]
#[ignore = "requires independent openssl executable; run through brynja-verify aes differential"]
fn openssl_independent_encrypt_and_decrypt_corpus() -> TestResult<()> {
    let executable = oracle_executable(std::env::var_os("BRYNJA_OPENSSL"))?;
    let version = Command::new(&executable).arg("version").output()?;
    if !version.status.success() {
        return Err("OpenSSL version probe failed".into());
    }
    println!(
        "Independent oracle: {}",
        String::from_utf8_lossy(&version.stdout).trim()
    );
    let mut random = 0x51de_cafe_2730_0001u64;
    let mut comparisons = 0usize;
    for case in 0..64 {
        let mut key_bytes = [0; 16];
        fill(&mut random, &mut key_bytes);
        if case == 0 {
            key_bytes.fill(0);
        }
        if case == 1 {
            key_bytes.fill(255);
        }
        let mut storage = [0; 16];
        let key = Aes128Key::new(&key_bytes, &mut storage).map_err(|_| "key admission")?;
        let mut expanded = [0; 176];
        let cached = Aes128ExpandedKey::new(&key_bytes, &mut expanded)
            .map_err(|_| "cached key admission")?;
        for decrypt in [false, true] {
            let mut input = [0; 512];
            fill(&mut random, &mut input);
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
                    key.encrypt_block_public(block, &mut output, PublicCiphertext::acknowledge())
                        .map_err(|_| "encrypt")?;
                    assert_eq!(&output, expected, "forward corpus {case}");
                }
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
                    cached
                        .encrypt_block_public(block, &mut output, PublicCiphertext::acknowledge())
                        .map_err(|_| "cached encrypt")?;
                    assert_eq!(&output, expected, "cached forward {case}");
                }
            }
        }
    }
    assert_eq!(comparisons, 4096);
    println!("AES_OPENSSL_COMPARISONS: 4096");
    println!("AES_CACHED_OPENSSL_COMPARISONS: 4096");
    Ok(())
}
