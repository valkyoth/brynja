//! Downstream byte/bit and lifecycle acceptance, without candidate evidence cfgs.
#![cfg(feature = "hardened-execution")]
use brynja_legacy_sha1::{
    BitString, PublicDeclassification, Sha1BackendHealth,
    hardened_execution::{Executor, Mode},
};

fn decode(text: &str) -> Vec<u8> {
    if text == "-" {
        return Vec::new();
    }
    assert_eq!(text.len() % 2, 0);
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let value = core::str::from_utf8(pair)
                .ok()
                .and_then(|s| u8::from_str_radix(s, 16).ok());
            assert!(value.is_some());
            value.unwrap_or_default()
        })
        .collect()
}

#[test]
fn nist_bit_vectors_and_all_output_profiles() -> Result<(), Box<dyn std::error::Error>> {
    for executor in [
        Executor::portable(),
        Executor::for_compiled_target(Mode::Prefer)?,
    ] {
        let mut count = 0;
        for line in include_str!("vectors/nist.txt")
            .lines()
            .filter(|line| !line.starts_with('#'))
        {
            let fields: Vec<_> = line.split('|').collect();
            assert_eq!(fields.len(), 3);
            let [length, message, expected] = fields.as_slice() else {
                return Err("vector shape".into());
            };
            let length = length.parse::<usize>()?;
            let message = decode(message);
            let expected = decode(expected);
            let width = if message.is_empty() {
                0
            } else if length % 8 == 0 {
                8
            } else {
                u8::try_from(length % 8)?
            };
            let input = BitString::new(&message, width).map_err(|_| "invalid vector bits")?;
            let mut output = [0xa5; 20];
            executor.hash_bits_public(input, &mut output, PublicDeclassification::acknowledge())?;
            assert_eq!(output.as_slice(), expected);
            {
                let secret = executor.hash_bits_secret(input, &mut output)?;
                assert_eq!(secret.expose(), expected);
            }
            assert_eq!(output, [0; 20]);
            let (bytes, partial) = input.split();
            for partition in [1, 7, 63, 64, 65, 257] {
                let mut stream = executor.start()?;
                for chunk in bytes.chunks(partition) {
                    stream.update(chunk)?;
                    stream.update(&[])?;
                }
                let (byte, valid) = partial.unwrap_or((0, 0));
                let tail = [byte];
                let tail = BitString::new(if valid == 0 { &[] } else { &tail }, valid)
                    .map_err(|_| "invalid tail bits")?;
                {
                    let secret = stream.finalize_bits_secret(tail, &mut output)?;
                    assert_eq!(secret.expose(), expected);
                }
                assert_eq!(output, [0; 20]);
            }
            count += 1;
        }
        assert_eq!(count, 529);
    }
    Ok(())
}

#[test]
fn byte_messages_and_million_byte_standard() -> Result<(), Box<dyn std::error::Error>> {
    for executor in [
        Executor::portable(),
        Executor::for_compiled_target(Mode::Prefer)?,
    ] {
        let mut output = [0xa5; 20];
        executor.hash_public(b"abc", &mut output, PublicDeclassification::acknowledge())?;
        assert_eq!(output, brynja_legacy_sha1::sha1(b"abc")?);
        {
            let secret = executor.hash_secret(b"abc", &mut output)?;
            assert_eq!(secret.expose(), brynja_legacy_sha1::sha1(b"abc")?);
        }
        assert_eq!(output, [0; 20]);
        let mut state = executor.start()?;
        for _ in 0..1000 {
            state.update(&[b'a'; 1000])?;
        }
        state.finalize_public(&mut output, PublicDeclassification::acknowledge())?;
        assert_eq!(
            output.as_slice(),
            decode("34aa973cd4c4daa4f61eeb2bdbad27316534016f")
        );
    }
    Ok(())
}

#[test]
fn revocation_cancellation_and_output_failures() -> Result<(), Box<dyn std::error::Error>> {
    for executor in [
        Executor::portable(),
        Executor::for_compiled_target(Mode::Prefer)?,
    ] {
        for length in [0, 1, 19, 21, 64] {
            let mut output = vec![0xa5; length];
            assert!(
                executor
                    .hash_public(
                        b"secret",
                        &mut output,
                        PublicDeclassification::acknowledge()
                    )
                    .is_err()
            );
            assert_eq!(output, vec![0xa5; length]);
            assert!(executor.hash_secret(b"secret", &mut output).is_err());
            assert_eq!(output, vec![0; length]);
        }
        let mut cancelled = executor.start()?;
        cancelled.update(b"secret")?;
        cancelled.cancel();
        let mut state = executor.start()?;
        state.update(b"secret")?;
        let sibling = executor.start()?;
        executor.quarantine();
        assert_eq!(executor.report().health, Sha1BackendHealth::Quarantined);
        assert!(state.update(&[]).is_err());
        let mut output = [0xa5; 20];
        assert!(
            state
                .finalize_public(&mut output, PublicDeclassification::acknowledge())
                .is_err()
        );
        assert_eq!(output, [0xa5; 20]);
        assert!(sibling.finalize_secret(&mut output).is_err());
        assert_eq!(output, [0; 20]);
        output.fill(0xa5);
        assert!(executor.hash_secret(b"x", &mut output).is_err());
        assert_eq!(output, [0; 20]);
    }
    Ok(())
}

#[test]
fn required_route_executes_without_candidate_admission() -> Result<(), Box<dyn std::error::Error>> {
    let prefer = Executor::for_compiled_target(Mode::Prefer)?;
    let compiled = cfg!(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "sha",
        target_feature = "sse2"
    )) || cfg!(all(
        target_arch = "aarch64",
        target_endian = "little",
        target_feature = "neon",
        target_feature = "sha2"
    ));
    assert_eq!(prefer.report().backend.is_some(), compiled);
    assert!(
        std::env::var_os("BRYNJA_REQUIRE_HARDENED_SHA1").is_none() || compiled,
        "required hardened SHA-1 API has no compiled CPU feature bundle"
    );
    if let Some(backend) = prefer.report().backend {
        assert!(!backend.is_admitted());
        let required = Executor::for_compiled_target(Mode::Require)?;
        assert_eq!(required.report().backend, Some(backend));
        let mut output = [0; 20];
        required.hash_public(b"abc", &mut output, PublicDeclassification::acknowledge())?;
        assert_eq!(output, brynja_legacy_sha1::sha1(b"abc")?);
        println!(
            "\nSHA1_HARDENED_OPERATIONAL: {}; actual hardened startup and digest passed",
            backend.as_str()
        );
    } else {
        assert!(Executor::for_compiled_target(Mode::Require).is_err());
    }
    assert_eq!(
        Executor::for_compiled_target(Mode::Portable)?
            .report()
            .backend,
        None
    );
    Ok(())
}
