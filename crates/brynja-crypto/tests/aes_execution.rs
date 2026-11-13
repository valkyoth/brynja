//! Explicit accelerated owners; positive hardware tests require the full ISA.
use brynja_crypto::aes::execution::{Authority, Kernel};

#[test]
fn unavailable_static_routes_reject_before_key_admission() {
    for kernel in [Kernel::X86AesNi, Kernel::ArmAes, Kernel::RiscVScalarAes] {
        if let Err(error) = kernel.check_compiled_target() {
            assert_eq!(Authority::new(kernel).err(), Some(error));
        }
    }
}

#[cfg(any(
    all(
        brynja_cpu_evidence,
        target_arch = "riscv64",
        target_endian = "little",
        target_feature = "zkne",
        target_feature = "zknd"
    ),
    all(
        target_arch = "x86_64",
        target_feature = "aes",
        target_feature = "sse2"
    ),
    all(
        target_arch = "aarch64",
        target_endian = "little",
        target_feature = "aes",
        target_feature = "neon"
    )
))]
mod native {
    use super::*;
    use brynja_crypto::aes::{PublicCiphertext, execution::*};

    fn authority() -> Result<Authority, Error> {
        Ok(Authority::new(if cfg!(target_arch = "x86_64") {
            Kernel::X86AesNi
        } else if cfg!(target_arch = "riscv64") {
            Kernel::RiscVScalarAes
        } else {
            Kernel::ArmAes
        })?)
    }

    fn field<const N: usize>(line: Option<&str>, prefix: &str) -> Result<[u8; N], Error> {
        let text = line
            .and_then(|s| s.strip_prefix(prefix))
            .ok_or(Error::SecretMemory)?;
        if text.len() != N.checked_mul(2).ok_or(Error::SecretMemory)?
            || !text.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(Error::SecretMemory);
        }
        let mut bytes = [0; N];
        for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
            *byte = u8::from_str_radix(
                core::str::from_utf8(pair).map_err(|_| Error::SecretMemory)?,
                16,
            )
            .map_err(|_| Error::SecretMemory)?;
        }
        Ok(bytes)
    }

    macro_rules! width {
        ($module:ident, $key:ident, $cached:ident, $k:literal, $s:literal, $bits:literal, $gfs:literal, $sbox:literal, $total:literal) => {
            mod $module {
                use super::*;

                #[test]
                fn nist_corpus_both_owners() -> Result<(), Error> {
                    let authority = authority()?;
                    let mut total = 0usize;
                    for (text, count) in [
                        (
                            include_str!(concat!(
                                "fixtures/aes",
                                $bits,
                                "/ECBGFSbox",
                                $bits,
                                ".rsp"
                            )),
                            $gfs,
                        ),
                        (
                            include_str!(concat!(
                                "fixtures/aes",
                                $bits,
                                "/ECBKeySbox",
                                $bits,
                                ".rsp"
                            )),
                            $sbox,
                        ),
                        (
                            include_str!(concat!(
                                "fixtures/aes",
                                $bits,
                                "/ECBVarKey",
                                $bits,
                                ".rsp"
                            )),
                            $bits,
                        ),
                        (
                            include_str!(concat!(
                                "fixtures/aes",
                                $bits,
                                "/ECBVarTxt",
                                $bits,
                                ".rsp"
                            )),
                            128,
                        ),
                    ] {
                        let mut lines = text
                            .lines()
                            .map(str::trim)
                            .filter(|s| !s.is_empty() && !s.starts_with('#'));
                        for (section, inverse, input, output) in [
                            ("[ENCRYPT]", false, "PLAINTEXT = ", "CIPHERTEXT = "),
                            ("[DECRYPT]", true, "CIPHERTEXT = ", "PLAINTEXT = "),
                        ] {
                            assert_eq!(lines.next(), Some(section));
                            for case in 0..count {
                                assert_eq!(lines.next(), Some(format!("COUNT = {case}").as_str()));
                                let input_key = field::<$k>(lines.next(), "KEY = ")?;
                                let input = field::<16>(lines.next(), input)?;
                                let expected = field::<16>(lines.next(), output)?;
                                let mut storage = [0xa5; $k];
                                let mut expanded = [0xa5; $s];
                                let key = $key::new(&authority, &input_key, &mut storage)?;
                                let cached = $cached::new(&authority, &input_key, &mut expanded)?;
                                for cache in [false, true] {
                                    let mut bytes = [0xa5; 16];
                                    let block = match (cache, inverse) {
                                        (false, false) => key.encrypt_block(&input, &mut bytes),
                                        (false, true) => key.decrypt_block(&input, &mut bytes),
                                        (true, false) => cached.encrypt_block(&input, &mut bytes),
                                        (true, true) => cached.decrypt_block(&input, &mut bytes),
                                    }?;
                                    assert_eq!(block.expose(), expected);
                                    block.clear();
                                    assert_eq!(bytes, [0; 16]);
                                    if !inverse {
                                        if cache {
                                            cached.encrypt_block_public(
                                                &input,
                                                &mut bytes,
                                                PublicCiphertext::acknowledge(),
                                            )?;
                                        } else {
                                            key.encrypt_block_public(
                                                &input,
                                                &mut bytes,
                                                PublicCiphertext::acknowledge(),
                                            )?;
                                        }
                                        assert_eq!(bytes, expected);
                                    }
                                }
                                key.clear();
                                cached.clear();
                                assert_eq!(storage, [0; $k]);
                                assert_eq!(expanded, [0; $s]);
                                total = total.checked_add(1).ok_or(Error::SecretMemory)?;
                            }
                        }
                        assert!(lines.next().is_none());
                    }
                    assert_eq!(total, $total);
                    println!("\nAES_EXECUTION_KAT_PASS: {}:{}", $bits, total);
                    Ok(())
                }

                #[test]
                fn quarantine_clears_secret_preserves_public_and_never_falls_back()
                -> Result<(), Error> {
                    let authority = authority()?;
                    let mut storage = [0xa5; $k];
                    let mut expanded = [0xa5; $s];
                    let key = $key::new(&authority, &[0x42; $k], &mut storage)?;
                    let cached = $cached::new(&authority, &[0x42; $k], &mut expanded)?;
                    authority.quarantine();
                    for cache in [false, true] {
                        for inverse in [false, true] {
                            let mut bytes = [0x99; 16];
                            let result = match (cache, inverse) {
                                (false, false) => key.encrypt_block(&[0x77; 16], &mut bytes),
                                (false, true) => key.decrypt_block(&[0x77; 16], &mut bytes),
                                (true, false) => cached.encrypt_block(&[0x77; 16], &mut bytes),
                                (true, true) => cached.decrypt_block(&[0x77; 16], &mut bytes),
                            };
                            assert!(matches!(
                                result,
                                Err(Error::Execution(brynja_crypto_cpu::aes::Error::Quarantined))
                            ));
                            drop(result);
                            assert_eq!(bytes, [0; 16]);
                        }
                        let mut public = [0x99; 16];
                        let result = if cache {
                            cached.encrypt_block_public(
                                &[0; 16],
                                &mut public,
                                PublicCiphertext::acknowledge(),
                            )
                        } else {
                            key.encrypt_block_public(
                                &[0; 16],
                                &mut public,
                                PublicCiphertext::acknowledge(),
                            )
                        };
                        assert!(matches!(
                            result,
                            Err(Error::Execution(brynja_crypto_cpu::aes::Error::Quarantined))
                        ));
                        assert_eq!(public, [0x99; 16]);
                    }
                    drop(key);
                    drop(cached);
                    assert_eq!(storage, [0; $k]);
                    assert_eq!(expanded, [0; $s]);
                    Ok(())
                }

                #[test]
                fn failed_constructor_clears_admitted_storage() -> Result<(), Error> {
                    let authority = authority()?;
                    authority.quarantine();
                    let mut storage = [0xa5; $k];
                    let mut expanded = [0xa5; $s];
                    assert!($key::new(&authority, &[0; $k], &mut storage).is_err());
                    assert!($cached::new(&authority, &[0; $k], &mut expanded).is_err());
                    assert_eq!(storage, [0; $k]);
                    assert_eq!(expanded, [0; $s]);
                    Ok(())
                }

                #[test]
                fn caller_unwind_clears_both_key_owners() -> Result<(), Error> {
                    let authority = authority()?;
                    let mut storage = [0xa5; $k];
                    let mut expanded = [0xa5; $s];
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                        || -> Result<(), Error> {
                            let _key = $key::new(&authority, &[0x42; $k], &mut storage)?;
                            let _cached = $cached::new(&authority, &[0x42; $k], &mut expanded)?;
                            std::panic::resume_unwind(Box::new(
                                "caller unwind after key construction",
                            ));
                        },
                    ));
                    assert!(outcome.is_err());
                    assert_eq!(storage, [0; $k]);
                    assert_eq!(expanded, [0; $s]);
                    // An unrelated caller unwind does not claim a kernel fault.
                    assert_eq!(authority.report().health, Health::Healthy);
                    Ok(())
                }
            }
        };
    }
    width!(
        aes128,
        Aes128Key,
        Aes128ExpandedKey,
        16,
        176,
        128,
        7,
        21,
        568
    );
    width!(
        aes192,
        Aes192Key,
        Aes192ExpandedKey,
        24,
        208,
        192,
        6,
        24,
        700
    );
    width!(
        aes256,
        Aes256Key,
        Aes256ExpandedKey,
        32,
        240,
        256,
        5,
        16,
        810
    );
}
