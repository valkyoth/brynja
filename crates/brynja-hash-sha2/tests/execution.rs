//! Complete ordinary execution boundary and lifecycle regression tests.
#![cfg(feature = "static-execution")]
use brynja_hash_sha2::{BitString, execution::*};

macro_rules! named_cases {
    ($name:ident, $ordinary:ident, $bits:ident, $block:expr) => {{
        for length in [0, 1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 257] {
            let bytes = vec![0xa5; length];
            let expected = brynja_hash_sha2::$ordinary(&bytes).map_err(|e| format!("{e:?}"))?;
            let output =
                $name::hash(Execution::portable(), &bytes).map_err(|e| format!("{e:?}"))?;
            assert_eq!(output.digest, expected);
            assert_eq!(output.report.message_blocks, (length / $block) as u128);
            assert_eq!(output.report.portable_iv_blocks, 0);
            assert_eq!(output.report.route, Route::Portable);
            for stride in [1, 19, 128] {
                let mut stream = $name::new(Execution::portable()).map_err(|e| format!("{e:?}"))?;
                for bytes in bytes.chunks(stride) {
                    stream.update(bytes).map_err(|e| format!("{e:?}"))?;
                }
                assert_eq!(stream.message_bytes() as u128, length as u128);
                assert_eq!(
                    stream.finalize().map_err(|e| format!("{e:?}"))?.digest,
                    expected
                );
            }
            for width in 1..=7 {
                let tail = [0x80];
                let mut whole = bytes.clone();
                whole.extend_from_slice(&tail);
                let bits = BitString::new(&whole, width).map_err(|e| format!("{e:?}"))?;
                let expected = brynja_hash_sha2::$bits(bits).map_err(|e| format!("{e:?}"))?;
                let result =
                    $name::hash_bits(Execution::portable(), bits).map_err(|e| format!("{e:?}"))?;
                assert_eq!(result.digest, expected);
                let mut state = $name::new(Execution::portable()).map_err(|e| format!("{e:?}"))?;
                state.update(&bytes).map_err(|e| format!("{e:?}"))?;
                assert_eq!(
                    state
                        .finalize_bits(BitString::new(&tail, width).map_err(|e| format!("{e:?}"))?)
                        .map_err(|e| format!("{e:?}"))?
                        .digest,
                    expected
                );
            }
        }
    }};
}

#[test]
fn every_named_identity_byte_bit_and_stream_boundary_matches() -> Result<(), String> {
    named_cases!(Sha224, sha224, sha224_bits, 64);
    named_cases!(Sha256, sha256, sha256_bits, 64);
    named_cases!(Sha384, sha384, sha384_bits, 128);
    named_cases!(Sha512, sha512, sha512_bits, 128);
    named_cases!(Sha512_224, sha512_224, sha512_224_bits, 128);
    named_cases!(Sha512_256, sha512_256, sha512_256_bits, 128);
    Ok(())
}

#[test]
fn portable_selection_and_unavailable_static_routes_are_explicit() -> Result<(), String> {
    let owner =
        StaticSelection::new(Kernel::ArmKeccak, Mode::Portable).map_err(|e| format!("{e:?}"))?;
    assert_eq!(
        Sha256::hash(owner.execution().map_err(|e| format!("{e:?}"))?, b"abc")
            .map_err(|e| format!("{e:?}"))?
            .report
            .route,
        Route::Portable
    );
    #[cfg(not(target_arch = "aarch64"))]
    {
        let preferred =
            StaticSelection::new(Kernel::ArmSha512, Mode::Prefer).map_err(|e| format!("{e:?}"))?;
        let output = Sha512::hash(preferred.execution().map_err(|e| format!("{e:?}"))?, b"abc")
            .map_err(|e| format!("{e:?}"))?;
        assert_eq!(
            output.report.route,
            Route::StaticFallback(brynja_crypto_cpu::static_execution::Error::WrongArchitecture)
        );
        assert!(StaticSelection::new(Kernel::ArmSha512, Mode::Require).is_err());
    }
    Ok(())
}

#[test]
fn public_length_errors_preserve_stream_and_accounting() -> Result<(), String> {
    let mut state = Sha256::new(Execution::portable()).map_err(|e| format!("{e:?}"))?;
    state.update(b"abc").map_err(|e| format!("{e:?}"))?;
    let report = state.report();
    assert_eq!(
        state.check_additional_bytes(u64::MAX),
        Err(Error::MessageTooLong)
    );
    assert_eq!(
        state.check_additional_bits(u64::MAX),
        Err(Error::MessageTooLong)
    );
    assert_eq!(state.report(), report);
    assert_eq!(state.message_bytes(), 3);
    assert_eq!(
        state.finalize().map_err(|e| format!("{e:?}"))?.digest,
        brynja_hash_sha2::sha256(b"abc").map_err(|e| format!("{e:?}"))?
    );
    Ok(())
}

#[test]
fn bounded_execution_lifecycle_smoke() -> Result<(), String> {
    let output = Sha512::hash(Execution::portable(), b"abc").map_err(|e| format!("{e:?}"))?;
    assert_eq!(
        output.digest,
        brynja_hash_sha2::sha512(b"abc").map_err(|e| format!("{e:?}"))?
    );
    assert_eq!(output.report.message_blocks, 0);
    assert_eq!(output.report.padding_blocks, 1);
    Ok(())
}

#[cfg(feature = "general-sha512-t")]
#[test]
fn every_general_parameter_has_exact_identity_and_portable_iv_report() -> Result<(), String> {
    for t in 1..512 {
        if t == 384 {
            continue;
        }
        let p = brynja_hash_sha2::Sha512TBits::new(t).map_err(|e| format!("{e:?}"))?;
        let output =
            Sha512T::hash(p, Execution::portable(), b"abc").map_err(|e| format!("{e:?}"))?;
        assert_eq!(
            output.digest,
            brynja_hash_sha2::sha512_t(p, b"abc").map_err(|e| format!("{e:?}"))?
        );
        assert_eq!(output.digest.parameter(), p);
        assert_eq!(output.report.portable_iv_blocks, 1);
        assert_eq!(output.report.padding_blocks, 1);
    }
    Ok(())
}
