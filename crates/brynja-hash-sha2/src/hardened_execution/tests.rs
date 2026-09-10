extern crate std;

use super::*;
use crate::BitString;
use brynja_crypto_cpu::static_execution::Authority;

fn route(owner: Option<&Authority>) -> Result<Execution<'_>, std::string::String> {
    match owner {
        Some(owner) => Execution::from_static(owner).map_err(|error| std::format!("{error:?}")),
        None => Ok(Execution::portable()),
    }
}
fn authority(wide: bool) -> Option<Authority> {
    let kernel = if wide {
        Kernel::ArmSha512
    } else if cfg!(target_arch = "x86_64") {
        Kernel::X86Sha256
    } else {
        Kernel::ArmSha256
    };
    Authority::new(kernel).ok()
}

macro_rules! cases {
    ($name:ident, $ordinary:ident, $bits:ident, $wide:expr, $size:expr, $block:expr) => {{
        let cpu = authority($wide);
        for owner in [None, cpu.as_ref()] {
            for length in [0, 1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 257] {
                let input = std::vec![0xa5;length];
                let expected = crate::$ordinary(&input).map_err(|error| std::format!("{error:?}"))?;
                let mut output = [0xa5; $size];
                let secret = $name::hash_secret(route(owner)?, &input, &mut output).map_err(|error| std::format!("{error:?}"))?;
                assert_eq!(secret.digest.expose(), expected.as_bytes());
                assert_eq!(secret.report.message_blocks, (length / $block) as u128);
                assert_eq!(secret.report.route, route(owner)?.route());
                drop(secret); assert_eq!(output, [0; $size]);
                for stride in [1, 19, 128] {
                    let mut stream = $name::new(route(owner)?).map_err(|error| std::format!("{error:?}"))?;
                    for chunk in input.chunks(stride) { stream.update(chunk).map_err(|error| std::format!("{error:?}"))?; }
                    assert_eq!(usize::try_from(stream.message_bytes()).map_err(|error| std::format!("{error:?}"))?, length);
                    assert_eq!(stream.check_additional_bytes(<$name>::MAX_MESSAGE_BYTES), if length == 0 { Ok(()) } else { Err(Error::MessageTooLong) });
                    stream.finalize_public(&mut output, PublicDeclassification::acknowledge()).map_err(|error| std::format!("{error:?}"))?;
                    assert_eq!(output.as_slice(), expected.as_bytes());
                }
                for width in 1..=7 {
                    let mut complete = input.clone(); complete.push(0x80);
                    let bits = BitString::new(&complete, width).map_err(|error| std::format!("{error:?}"))?;
                    let expected = crate::$bits(bits).map_err(|error| std::format!("{error:?}"))?;
                    let secret = $name::hash_bits_secret(route(owner)?, bits, &mut output).map_err(|error| std::format!("{error:?}"))?;
                    assert_eq!(secret.digest.expose(), expected.as_bytes()); drop(secret);
                    let mut stream = $name::new(route(owner)?).map_err(|error| std::format!("{error:?}"))?; stream.update(&input).map_err(|error| std::format!("{error:?}"))?;
                    stream.finalize_bits_public(BitString::new(&[0x80], width).map_err(|error| std::format!("{error:?}"))?, &mut output, PublicDeclassification::acknowledge()).map_err(|error| std::format!("{error:?}"))?;
                    assert_eq!(output.as_slice(), expected.as_bytes());
                }
                let mut wrong = [0xa5; $size + 1];
                assert!(matches!($name::hash_secret(route(owner)?, &input, &mut wrong), Err(Error::OutputLength)));
                assert_eq!(wrong, [0; $size + 1]);
                wrong.fill(0xa5);
                assert_eq!($name::hash_public(route(owner)?, &input, &mut wrong, PublicDeclassification::acknowledge()), Err(Error::OutputLength));
                assert_eq!(wrong, [0xa5; $size + 1]);
            }
        }
    }};
}

#[test]
fn all_named_byte_bit_stream_outputs_and_failures_match() -> Result<(), std::string::String> {
    cases!(Sha224, sha224, sha224_bits, false, 28, 64);
    cases!(Sha256, sha256, sha256_bits, false, 32, 64);
    cases!(Sha384, sha384, sha384_bits, true, 48, 128);
    cases!(Sha512, sha512, sha512_bits, true, 64, 128);
    cases!(Sha512_224, sha512_224, sha512_224_bits, true, 28, 128);
    cases!(Sha512_256, sha512_256, sha512_256_bits, true, 32, 128);
    Ok(())
}

#[test]
fn quarantine_clears_live_stream_and_failed_secret_destination() -> Result<(), std::string::String>
{
    let Some(owner) = authority(false) else {
        return Ok(());
    };
    let mut state = Sha256::new(route(Some(&owner))?).map_err(|error| std::format!("{error:?}"))?;
    state
        .update(b"confidential pending input")
        .map_err(|error| std::format!("{error:?}"))?;
    owner.quarantine();
    assert!(matches!(state.update(&[]), Err(Error::Backend(_))));
    assert_eq!(state.update(b"retry"), Err(Error::Failed));
    assert_eq!(state.message_bytes(), 0);
    let mut output = [0xa5; 32];
    assert!(matches!(
        state.finalize_secret(&mut output),
        Err(Error::Failed)
    ));
    assert_eq!(output, [0; 32]);
    assert!(Execution::from_static(&owner).is_err());
    Ok(())
}

#[test]
fn output_owner_clears_during_recoverable_unwind() -> Result<(), std::string::String> {
    let mut output = [0xa5; 32];
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || -> Result<(), std::string::String> {
            let _digest = Sha256::hash_secret(Execution::portable(), b"secret", &mut output)
                .map_err(|error| std::format!("{error:?}"))?;
            std::panic::resume_unwind(std::boxed::Box::new("secret result unwind probe"));
        },
    ));
    assert!(result.is_err());
    assert_eq!(output, [0; 32]);
    Ok(())
}

#[cfg(feature = "general-sha512-t")]
#[test]
fn all_510_general_parameters_byte_bit_and_secret_identity_match() -> Result<(), std::string::String>
{
    let cpu = authority(true);
    for owner in [None, cpu.as_ref()] {
        for t in 1_u16..512 {
            let Ok(parameter) = crate::Sha512TBits::new(t) else {
                assert_eq!(t, 384);
                continue;
            };
            for length in [0, 1, 111, 112, 127, 128, 129, 255, 257] {
                let mut input = std::vec![0xa5;length];
                input.push(0x80);
                let bits =
                    BitString::new(&input, u8::try_from((t % 7).saturating_add(1)).unwrap_or(0))
                        .map_err(|error| std::format!("{error:?}"))?;
                let expected = crate::sha512_t_bits(parameter, bits)
                    .map_err(|error| std::format!("{error:?}"))?;
                let mut output = std::vec![0xa5;parameter.output_bytes()];
                let secret = Sha512T::hash_bits_secret(parameter, route(owner)?, bits, &mut output)
                    .map_err(|error| std::format!("{error:?}"))?;
                assert_eq!(secret.digest.parameter(), parameter);
                assert_eq!(secret.digest.as_bytes(), expected.as_bytes());
                assert_eq!(secret.report.portable_iv_blocks, 1);
                drop(secret);
                assert!(output.iter().all(|b| *b == 0));
                let mut stream = Sha512T::new(parameter, route(owner)?)
                    .map_err(|error| std::format!("{error:?}"))?;
                for chunk in input.get(..length).ok_or("input range")?.chunks(19) {
                    stream
                        .update(chunk)
                        .map_err(|error| std::format!("{error:?}"))?;
                }
                let public = stream
                    .finalize_bits_public(
                        BitString::new(
                            &[0x80],
                            u8::try_from((t % 7).saturating_add(1)).unwrap_or(0),
                        )
                        .map_err(|error| std::format!("{error:?}"))?,
                        PublicDeclassification::acknowledge(),
                    )
                    .map_err(|error| std::format!("{error:?}"))?;
                assert_eq!(public.digest, expected);
            }
        }
    }
    Ok(())
}
