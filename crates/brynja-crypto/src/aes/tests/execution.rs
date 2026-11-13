use super::*;
use crate::aes::execution::{self as accelerated, Authority, Health, Kernel};

fn authority() -> Result<Authority, accelerated::Error> {
    Ok(Authority::new(if cfg!(target_arch = "x86_64") {
        Kernel::X86AesNi
    } else if cfg!(target_arch = "riscv64") {
        Kernel::RiscVScalarAes
    } else {
        Kernel::ArmAes
    })?)
}

macro_rules! operations {
    ($key:ident, $k:literal, $s:literal, $points:literal, $mask:literal) => {
        for point in 0..$points {
            for unwind in [false, true] {
                for action in 0..3 {
                    let authority = authority()?;
                    let mut storage = [0xa5; $k];
                    let key = accelerated::$key::new(&authority, &[0x42; $k], &mut storage)?;
                    let mut output = [0x99; 16];
                    EXPANSION_POINT.set(0);
                    CLEARED.set(0);
                    EXPANSION_FAIL.set(Some((point, unwind)));
                    let result = catch_unwind(AssertUnwindSafe(|| match action {
                        0 => key
                            .encrypt_block(&[0x77; 16], &mut output)
                            .map(|b| b.clear()),
                        1 => key
                            .decrypt_block(&[0x77; 16], &mut output)
                            .map(|b| b.clear()),
                        _ => key.encrypt_block_public(
                            &[0x77; 16],
                            &mut output,
                            PublicCiphertext::acknowledge(),
                        ),
                    }));
                    EXPANSION_FAIL.set(None);
                    if unwind {
                        assert!(result.is_err());
                    } else {
                        assert!(matches!(result, Ok(Err(accelerated::Error::SecretMemory))));
                    }
                    assert_eq!(output, if action == 2 { [0x99; 16] } else { [0; 16] });
                    assert_eq!(CLEARED.get(), $mask);
                    assert_eq!(key.report().health, Health::Quarantined);
                    assert!(key.encrypt_block(&[0; 16], &mut output).is_err());
                    key.clear();
                    assert_eq!(storage, [0; $k]);
                }
            }
        }
    };
}

#[test]
fn every_expansion_error_and_unwind_clears_and_quarantines() -> Result<(), accelerated::Error> {
    operations!(Aes128Key, 16, 176, 2, 1);
    operations!(Aes192Key, 24, 208, 2, 8);
    operations!(Aes256Key, 32, 240, 2, 16);
    std::println!("AES_EXECUTION_EXPANSION_OPERATION_FAULT_PASS: 36");
    Ok(())
}

macro_rules! constructors {
    ($key:ident, $k:literal, $s:literal, $points:literal, $mask:literal) => {
        for point in 0..$points {
            for unwind in [false, true] {
                let authority = authority()?;
                let mut storage = [0xa5; $s];
                EXPANSION_POINT.set(0);
                CLEARED.set(0);
                EXPANSION_FAIL.set(Some((point, unwind)));
                let result = catch_unwind(AssertUnwindSafe(|| {
                    accelerated::$key::new(&authority, &[0x42; $k], &mut storage)
                        .map(|key| key.clear())
                }));
                EXPANSION_FAIL.set(None);
                if unwind {
                    assert!(result.is_err());
                } else {
                    assert!(matches!(result, Ok(Err(accelerated::Error::SecretMemory))));
                }
                assert_eq!(storage, [0; $s]);
                assert_eq!(CLEARED.get(), $mask);
                assert_eq!(authority.report().health, Health::Quarantined);
                assert!(authority.session().is_err());
            }
        }
    };
}

#[test]
fn cached_constructor_errors_and_unwinds_clear_and_quarantine() -> Result<(), accelerated::Error> {
    constructors!(Aes128ExpandedKey, 16, 176, 2, 1);
    constructors!(Aes192ExpandedKey, 24, 208, 2, 8);
    constructors!(Aes256ExpandedKey, 32, 240, 2, 16);
    std::println!("AES_EXECUTION_EXPANSION_CONSTRUCTOR_FAULT_PASS: 12");
    Ok(())
}

#[test]
fn cached_operations_never_reexpand() -> Result<(), accelerated::Error> {
    macro_rules! check {
        ($key:ident, $k:literal, $s:literal) => {{
            let authority = authority()?;
            let mut storage = [0xa5; $s];
            EXPANSION_POINT.set(0);
            let key = accelerated::$key::new(&authority, &[0x42; $k], &mut storage)?;
            assert_eq!(EXPANSION_POINT.get(), 2);
            EXPANSION_POINT.set(0);
            EXPANSION_FAIL.set(Some((0, false)));
            let result = (|| -> Result<(), accelerated::Error> {
                let mut output = [0x99; 16];
                key.encrypt_block(&[0; 16], &mut output)?.clear();
                key.decrypt_block(&[0; 16], &mut output)?.clear();
                key.encrypt_block_public(&[0; 16], &mut output, PublicCiphertext::acknowledge())?;
                Ok(())
            })();
            EXPANSION_FAIL.set(None);
            result?;
            assert_eq!(EXPANSION_POINT.get(), 0);
            assert_eq!(key.report().health, Health::Healthy);
            key.clear();
            assert_eq!(storage, [0; $s]);
        }};
    }
    check!(Aes128ExpandedKey, 16, 176);
    check!(Aes192ExpandedKey, 24, 208);
    check!(Aes256ExpandedKey, 32, 240);
    std::println!("AES_EXECUTION_EXPANSION_CACHED_PASS: 3");
    Ok(())
}

#[test]
fn revocation_after_expansion_prevents_owners_and_output() -> Result<(), accelerated::Error> {
    macro_rules! check {
        ($raw:ident, $cached:ident, $k:literal, $s:literal, $mask:literal) => {{
            let authority = authority()?;
            let mut storage = [0xa5; $s];
            EXPANSION_POINT.set(0);
            CLEARED.set(0);
            EXECUTION_REVOKE.set(true);
            let result = accelerated::$cached::new(&authority, &[0x42; $k], &mut storage)
                .map(|key| key.clear());
            EXECUTION_REVOKE.set(false);
            assert!(matches!(
                result,
                Err(accelerated::Error::Execution(
                    brynja_crypto_cpu::aes::Error::Quarantined
                ))
            ));
            assert_eq!(storage, [0; $s]);
            assert_eq!(CLEARED.get(), $mask);
            for action in 0..3 {
                let authority = self::authority()?;
                let mut storage = [0xa5; $k];
                let key = accelerated::$raw::new(&authority, &[0x42; $k], &mut storage)?;
                let mut output = [0x99; 16];
                EXPANSION_POINT.set(0);
                CLEARED.set(0);
                EXECUTION_REVOKE.set(true);
                let result = match action {
                    0 => key.encrypt_block(&[0; 16], &mut output).map(|b| b.clear()),
                    1 => key.decrypt_block(&[0; 16], &mut output).map(|b| b.clear()),
                    _ => key.encrypt_block_public(
                        &[0; 16],
                        &mut output,
                        PublicCiphertext::acknowledge(),
                    ),
                };
                EXECUTION_REVOKE.set(false);
                assert!(matches!(
                    result,
                    Err(accelerated::Error::Execution(
                        brynja_crypto_cpu::aes::Error::Quarantined
                    ))
                ));
                assert_eq!(output, if action == 2 { [0x99; 16] } else { [0; 16] });
                assert_eq!(CLEARED.get(), $mask);
                key.clear();
                assert_eq!(storage, [0; $k]);
            }
        }};
    }
    check!(Aes128Key, Aes128ExpandedKey, 16, 176, 1);
    check!(Aes192Key, Aes192ExpandedKey, 24, 208, 8);
    check!(Aes256Key, Aes256ExpandedKey, 32, 240, 16);
    std::println!("AES_EXECUTION_EXPANSION_REVOKE_PASS: 12");
    Ok(())
}
