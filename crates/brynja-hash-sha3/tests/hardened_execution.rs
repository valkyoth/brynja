//! Hardened native execution, portable equivalence and output ownership tests.
#![cfg(feature = "hardened-execution")]

use brynja_crypto_cpu::static_execution::{Authority, Kernel};
use brynja_hash_sha3::{
    self as portable, Fips202BitString, Fips202Output, hardened_execution as cpu,
};

fn error(value: impl core::fmt::Debug) -> String {
    format!("{value:?}")
}
fn authority() -> Result<Option<Authority>, String> {
    let kernel = if cfg!(target_arch = "aarch64") {
        Kernel::ArmKeccak
    } else {
        Kernel::X86Keccak
    };
    let compiled = cfg!(all(target_arch = "x86_64", target_feature = "avx2"))
        || cfg!(all(target_arch = "aarch64", target_feature = "sha3"));
    if compiled {
        Ok(Some(Authority::new(kernel).map_err(error)?))
    } else {
        Ok(None)
    }
}
fn session(owner: &Authority) -> Result<cpu::KeccakSession<'_>, String> {
    cpu::KeccakSession::from_static(owner).map_err(error)
}

#[test]
fn four_fixed_identities_all_tail_widths_and_padding_boundaries() -> Result<(), String> {
    let Some(owner) = authority()? else {
        return Ok(());
    };
    let mut cases = 0;
    for length in [
        0, 1, 70, 71, 72, 73, 102, 103, 104, 105, 134, 135, 136, 137, 142, 143, 144, 145, 166, 167,
        168, 169, 335,
    ] {
        for valid in 1..=8 {
            let mut input = vec![0xa5; length];
            if let Some(last) = input.last_mut() {
                *last &= u8::MAX >> (8 - valid);
            }
            let tail = Fips202BitString::new(&input, if length == 0 { 0 } else { valid })
                .map_err(error)?;
            macro_rules! check {
                ($name:ident, $width:literal) => {{
                    let expected = portable::$name::new().finalize_bits(tail).map_err(error)?;
                    let mut output = [0x99; $width];
                    cpu::$name::new(session(&owner)?)
                        .map_err(error)?
                        .finalize_bits_public(
                            tail,
                            &mut output,
                            cpu::Sha3PublicDeclassification::acknowledge(),
                        )
                        .map_err(error)?;
                    assert_eq!(&output[..], expected.as_bytes());
                    let secret = cpu::$name::new(session(&owner)?)
                        .map_err(error)?
                        .finalize_bits_secret(tail, &mut output)
                        .map_err(error)?;
                    assert_eq!(secret.expose(), expected.as_bytes());
                    drop(secret);
                    assert!(output.iter().all(|byte| *byte == 0));
                    cases += 1;
                }};
            }
            check!(Sha3_224, 28);
            check!(Sha3_256, 32);
            check!(Sha3_384, 48);
            check!(Sha3_512, 64);
        }
    }
    assert_eq!(cases, 736);
    Ok(())
}

#[test]
fn shake_and_cshake_streams_partial_outputs_and_secret_ownership() -> Result<(), String> {
    let Some(owner) = authority()? else {
        return Ok(());
    };
    for length in [0, 1, 135, 136, 167, 168, 169, 335, 336] {
        let input = vec![0x96; length];
        for valid in 1..=8 {
            let mut expected = [0; 337];
            let mut output = [0xa5; 337];
            let mut scratch = [0x93; 337];
            macro_rules! xof {
                ($name:ident, $portable:expr, $cpu:expr) => {{
                    let mut reference = $portable;
                    let mut state = $cpu;
                    for chunk in input.chunks(13) {
                        reference.update(chunk).map_err(error)?;
                        state.update(chunk).map_err(error)?;
                    }
                    let mut reference = reference.finalize_xof();
                    let mut reader = state.finalize_xof().map_err(error)?;
                    reference.squeeze(&mut expected[..17]).map_err(error)?;
                    reader
                        .squeeze_public(
                            &mut output[..17],
                            cpu::Sha3PublicDeclassification::acknowledge(),
                        )
                        .map_err(error)?;
                    reference
                        .squeeze_final_bits(
                            Fips202Output::new(&mut expected[17..], valid).map_err(error)?,
                        )
                        .map_err(error)?;
                    reader
                        .squeeze_final_bits_public(
                            Fips202Output::new(&mut output[17..], valid).map_err(error)?,
                            &mut scratch,
                            cpu::Sha3PublicDeclassification::acknowledge(),
                        )
                        .map_err(error)?;
                    assert_eq!(output, expected);
                    assert!(scratch.iter().all(|byte| *byte == 0));
                    let mut state = $cpu;
                    state.update(&input).map_err(error)?;
                    let mut reader = state.finalize_xof().map_err(error)?;
                    drop(reader.squeeze_secret(&mut [0; 17]).map_err(error)?);
                    let secret = reader
                        .squeeze_final_bits_secret(&mut output[17..], valid)
                        .map_err(error)?;
                    assert_eq!(secret.expose(), &expected[17..]);
                    drop(secret);
                    assert!(output[17..].iter().all(|byte| *byte == 0));
                }};
            }
            xof!(
                Shake128,
                portable::Shake128::new(),
                cpu::Shake128::new(session(&owner)?).map_err(error)?
            );
            xof!(
                Shake256,
                portable::Shake256::new(),
                cpu::Shake256::new(session(&owner)?).map_err(error)?
            );
            for customized in [false, true] {
                let n = Fips202BitString::new(
                    if customized { &[3] } else { &[] },
                    if customized { 2 } else { 0 },
                )
                .map_err(error)?;
                let s = Fips202BitString::new(
                    if customized { &[7] } else { &[] },
                    if customized { 3 } else { 0 },
                )
                .map_err(error)?;
                xof!(
                    Cshake128,
                    portable::Cshake128::new_bits(n, s).map_err(error)?,
                    cpu::Cshake128::new_bits(session(&owner)?, n, s).map_err(error)?
                );
                xof!(
                    Cshake256,
                    portable::Cshake256::new_bits(n, s).map_err(error)?,
                    cpu::Cshake256::new_bits(session(&owner)?, n, s).map_err(error)?
                );
            }
        }
    }
    Ok(())
}

#[test]
fn cancellation_and_backend_failure_clear_secrets_preserve_public_destinations()
-> Result<(), String> {
    let Some(owner) = authority()? else {
        return Ok(());
    };
    let mut state = cpu::Sha3_256::new(session(&owner)?).map_err(error)?;
    state.update(b"secret").map_err(error)?;
    state.cancel();
    assert_eq!(state.update(b"again"), Err(cpu::Error::Terminal));
    let mut secret = [0xa5; 32];
    assert!(state.finalize_secret(&mut secret).is_err());
    assert_eq!(secret, [0; 32]);
    let fixed = cpu::Sha3_256::new(session(&owner)?).map_err(error)?;
    let mut reader = cpu::Shake256::new(session(&owner)?)
        .map_err(error)?
        .finalize_xof()
        .map_err(error)?;
    owner.quarantine();
    secret.fill(0xa5);
    assert!(fixed.finalize_secret(&mut secret).is_err());
    assert_eq!(secret, [0; 32]);
    let mut public = [0xa5; 32];
    let mut scratch = [0x93; 64];
    assert!(
        reader
            .squeeze_public_with_scratch(
                &mut public,
                &mut scratch,
                cpu::Sha3PublicDeclassification::acknowledge()
            )
            .is_err()
    );
    assert_eq!(public, [0xa5; 32]);
    assert_eq!(scratch, [0; 64]);
    assert!(reader.squeeze_secret(&mut secret).is_err());
    assert_eq!(secret, [0; 32]);
    Ok(())
}

#[test]
fn inplace_cshake_transition_and_partial_message_match_portable() -> Result<(), String> {
    let Some(owner) = authority()? else {
        return Ok(());
    };
    for length in [135, 136, 137, 167, 168, 169] {
        for valid in 1..8 {
            let mut input = vec![0x96; length];
            if let Some(last) = input.last_mut() {
                *last &= u8::MAX >> (8 - valid);
            }
            let bits = Fips202BitString::new(&input, valid).map_err(error)?;
            macro_rules! check {
                ($name:ident,$reference:expr,$state:expr) => {{
                    let mut expected = [0; 201];
                    $reference
                        .finalize_bits_xof(bits)
                        .map_err(error)?
                        .squeeze_final_bits(Fips202Output::new(&mut expected, 3).map_err(error)?)
                        .map_err(error)?;
                    let mut state = $state;
                    state.enter_squeezing_in_place(bits).map_err(error)?;
                    let mut output = [0xa5; 201];
                    let first = state
                        .squeeze_secret_in_place(&mut output[..17])
                        .map_err(error)?;
                    assert_eq!(first.expose(), &expected[..17]);
                    drop(first);
                    let last = state
                        .squeeze_final_bits_secret_in_place(&mut output[17..], 3)
                        .map_err(error)?;
                    assert_eq!(last.expose(), &expected[17..]);
                    drop(last);
                    assert_eq!(output, [0; 201]);
                    assert!(state.squeeze_secret_in_place(&mut output).is_err());
                    assert_eq!(state.update(b"again"), Err(cpu::Error::Terminal));
                    let mut state = $state;
                    state.enter_squeezing_in_place(bits).map_err(error)?;
                    let mut scratch = [0xa5; 205];
                    state
                        .squeeze_final_bits_public_in_place(
                            Fips202Output::new(&mut output, 3).map_err(error)?,
                            &mut scratch,
                            cpu::Sha3PublicDeclassification::acknowledge(),
                        )
                        .map_err(error)?;
                    assert_eq!(output, expected);
                    assert_eq!(scratch, [0; 205]);
                    assert_eq!(state.update(b"again"), Err(cpu::Error::Terminal));
                }};
            }
            check!(
                Shake128,
                portable::Shake128::new(),
                cpu::Shake128::new(session(&owner)?).map_err(error)?
            );
            check!(
                Shake256,
                portable::Shake256::new(),
                cpu::Shake256::new(session(&owner)?).map_err(error)?
            );
            check!(
                Cshake128,
                portable::Cshake128::new(b"N", b"S").map_err(error)?,
                cpu::Cshake128::new(session(&owner)?, b"N", b"S").map_err(error)?
            );
            check!(
                Cshake256,
                portable::Cshake256::new(b"N", b"S").map_err(error)?,
                cpu::Cshake256::new(session(&owner)?, b"N", b"S").map_err(error)?
            );
        }
    }
    Ok(())
}
