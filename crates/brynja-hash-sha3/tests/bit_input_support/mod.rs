use super::{Fips202BitString, Fips202Output};

pub(super) fn check_scoped_fixed(
    algorithm: &str,
    input: Fips202BitString<'_>,
    expected: &[u8],
    output_bits: usize,
) -> Result<(), brynja_hash_sha3::hardened_execution::Error> {
    use brynja_crypto_cpu::static_execution::{Authority, Kernel};
    use brynja_hash_sha3::hardened_execution::{Error, KeccakSession, in_place::*};
    let kernel = if cfg!(target_arch = "aarch64") {
        Kernel::ArmKeccak
    } else {
        Kernel::X86Keccak
    };
    let selected = Authority::new(kernel);
    if std::env::var_os("BRYNJA_REQUIRE_SCOPED_KECCAK").is_some() {
        assert!(selected.is_ok());
    }
    let Ok(owner) = selected else {
        return Ok(());
    };
    macro_rules! check {
        ($workspace:ident) => {{
            let mut workspace =
                $workspace::new(KeccakSession::from_static(&owner).map_err(Error::Backend)?)?;
            let mut output = vec![0xa5; expected.len()];
            let secret =
                workspace.with(|state| state.finalize_bits_secret(input, &mut output))??;
            assert_eq!(secret.expose(), expected);
            drop(secret);
            assert!(output.iter().all(|b| *b == 0));
            workspace.with(|state| {
                state.finalize_bits_public(
                    input,
                    &mut output,
                    brynja_hash_sha3::Sha3PublicDeclassification::acknowledge(),
                )
            })??;
            assert_eq!(output, expected);
        }};
    }
    macro_rules! xof {
        ($workspace:ident) => {{
            let mut workspace =
                $workspace::new(KeccakSession::from_static(&owner).map_err(Error::Backend)?)?;
            let valid = u8::try_from(output_bits % 8).map_err(|_| Error::OutputLength)?;
            let valid = if !expected.is_empty() && valid == 0 {
                8
            } else {
                valid
            };
            let mut output = vec![0xa5; expected.len()];
            let secret = workspace.with(|state| {
                state
                    .finalize_bits_xof(input)?
                    .squeeze_final_bits_secret(&mut output, valid)
            })??;
            assert_eq!(secret.expose(), expected);
            drop(secret);
            assert!(output.iter().all(|b| *b == 0));
            let mut scratch = vec![0xa5; expected.len()];
            workspace.with(|state| {
                state.finalize_bits_xof(input)?.squeeze_final_bits_public(
                    Fips202Output::new(&mut output, valid).map_err(|_| Error::OutputLength)?,
                    &mut scratch,
                    brynja_hash_sha3::Sha3PublicDeclassification::acknowledge(),
                )
            })??;
            assert_eq!(output, expected);
            assert!(scratch.iter().all(|b| *b == 0));
        }};
    }
    match algorithm {
        "sha3-224" => check!(Sha3_224Workspace),
        "sha3-256" => check!(Sha3_256Workspace),
        "sha3-384" => check!(Sha3_384Workspace),
        "sha3-512" => check!(Sha3_512Workspace),
        "shake128" => xof!(Shake128Workspace),
        "shake256" => xof!(Shake256Workspace),
        _ => {}
    }
    Ok(())
}
