//! Opt-in public-data SHA-3/SHAKE execution acceptance.
#![cfg(feature = "static-execution")]
mod execution_cases;
use brynja_hash_sha3::execution as api;
use execution_cases as cases;

#[test]
fn explicit_public_inputs_cover_every_identity_and_byte_entry_point()
-> Result<(), Box<dyn std::error::Error>> {
    macro_rules! fixed {
        ($name:ident, $function:ident) => {{
            let expected = brynja_hash_sha3::$function(b"public input").map_err(|_| "hash")?;
            let one_shot = api::$name::hash(
                api::Execution::portable(),
                api::Public::new(b"public input"),
            )?;
            let mut streaming = api::$name::new(api::Execution::portable())?;
            streaming.update(api::Public::new(b"public "))?;
            streaming.update(api::Public::new(b"input"))?;
            assert_eq!(one_shot.digest, expected);
            assert_eq!(streaming.finalize()?.digest, expected);
        }};
    }
    fixed!(Sha3_224, sha3_224);
    fixed!(Sha3_256, sha3_256);
    fixed!(Sha3_384, sha3_384);
    fixed!(Sha3_512, sha3_512);
    macro_rules! shake {
        ($name:ident, $function:ident) => {{
            let mut expected = [0; 169];
            brynja_hash_sha3::$function(b"public input", &mut expected).map_err(|_| "XOF")?;
            let mut one_shot = [0xa5; 169];
            api::$name::hash_with_scratch(
                api::Execution::portable(),
                api::Public::new(b"public input"),
                &mut one_shot,
                &mut [0; 169],
            )?;
            let mut state = api::$name::new(api::Execution::portable())?;
            state.update(api::Public::new(b"public input"))?;
            let mut streaming = [0xa5; 169];
            state
                .finalize_xof()?
                .squeeze_with_scratch(&mut streaming, &mut [0; 169])?;
            assert_eq!(one_shot, expected);
            assert_eq!(streaming, expected);
        }};
    }
    shake!(Shake128, shake128);
    shake!(Shake256, shake256);
    Ok(())
}

#[test]
fn execution_smoke() -> Result<(), Box<dyn std::error::Error>> {
    let output = api::Sha3_256::hash(api::Execution::portable(), api::Public::new(b"abc"))?;
    assert_eq!(
        output.digest,
        brynja_hash_sha3::sha3_256(b"abc").map_err(|_| "hash")?
    );
    let mut reader = api::Shake128::new(api::Execution::portable())?.finalize_xof()?;
    let mut output = [0; 169];
    reader.squeeze_with_scratch(&mut output, &mut [0; 169])?;
    let mut expected = [0; 169];
    brynja_hash_sha3::shake128(b"", &mut expected).map_err(|_| "XOF")?;
    assert_eq!(output, expected);
    assert_eq!(reader.report().squeeze_permutations, 1);
    Ok(())
}

#[test]
fn portable_and_available_static_routes_match_all_cases() -> Result<(), Box<dyn std::error::Error>>
{
    assert_eq!(cases::run(|| Ok(api::Execution::portable()))?, 1084);
    let kernel = if cfg!(target_arch = "aarch64") {
        api::Kernel::ArmKeccak
    } else {
        api::Kernel::X86Keccak
    };
    let selection = api::StaticSelection::new(kernel, api::Mode::Prefer)?;
    assert_eq!(cases::run(|| Ok(selection.execution()?))?, 1084);
    Ok(())
}

#[test]
fn quarantine_and_wrong_operation_cannot_fallback_or_change_output()
-> Result<(), Box<dyn std::error::Error>> {
    assert!(api::StaticSelection::new(api::Kernel::ArmSha256, api::Mode::Prefer).is_err());
    let kernel = if cfg!(target_arch = "aarch64") {
        api::Kernel::ArmKeccak
    } else {
        api::Kernel::X86Keccak
    };
    let selection = api::StaticSelection::new(kernel, api::Mode::Prefer)?;
    let mut stream = api::Sha3_256::new(selection.execution()?)?;
    let mut reader = api::Shake128::new(selection.execution()?)?.finalize_xof()?;
    if matches!(reader.report().route, api::Route::Static(_)) {
        let report = reader.report();
        let mut output = [0xa5; 400];
        selection.quarantine();
        assert!(
            reader
                .squeeze_with_scratch(&mut output, &mut [0; 400])
                .is_err()
        );
        assert_eq!(output, [0xa5; 400]);
        assert_eq!(reader.output_bytes(), 0);
        assert_eq!(reader.report(), report);
        assert!(reader.squeeze(&mut []).is_err());
        assert!(stream.update(api::Public::new(&[])).is_err());
        assert_eq!(stream.message_bytes(), 0);
        assert!(stream.finalize().is_err());
    }
    Ok(())
}
