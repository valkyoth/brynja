use super::native::{clear, routes};
use super::*;
#[test]
fn all_sponge_identities_canonical_bits_and_long_outputs() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    for route in routes()
        .into_iter()
        .filter(|r| matches!(r, Route::Keccak(_)))
    {
        let mut session = Session::new(route, limits())?;
        let mut cases = 0;
        for algorithm in [
            keccak::Algorithm::Sha3_224,
            keccak::Algorithm::Sha3_256,
            keccak::Algorithm::Sha3_384,
            keccak::Algorithm::Sha3_512,
            keccak::Algorithm::Shake128,
            keccak::Algorithm::Shake256,
            keccak::Algorithm::Cshake128,
            keccak::Algorithm::Cshake256,
        ] {
            for width in [0usize, 1, 257, 32777] {
                let width = algorithm.fixed_output_bits().unwrap_or(width);
                for valid in 1u8..=8 {
                    let mut bytes = vec![0x63; 337];
                    if let Some(last) = bytes.last_mut() {
                        *last &= u8::MAX >> (8 - valid);
                    }
                    let raw = core::array::from_fn(|i| {
                        if i < 4 {
                            Some(Input {
                                algorithm: Algorithm::Keccak(algorithm, width),
                                message: Bits {
                                    bytes: &bytes,
                                    valid_bits: valid,
                                },
                                name: if matches!(
                                    algorithm,
                                    keccak::Algorithm::Cshake128 | keccak::Algorithm::Cshake256
                                ) {
                                    Bits {
                                        bytes: &[3],
                                        valid_bits: 2,
                                    }
                                } else {
                                    Bits::bytes(&[])
                                },
                                customization: if matches!(
                                    algorithm,
                                    keccak::Algorithm::Cshake128 | keccak::Algorithm::Cshake256
                                ) {
                                    Bits {
                                        bytes: &[1],
                                        valid_bits: 1,
                                    }
                                } else {
                                    Bits::bytes(&[])
                                },
                            })
                        } else {
                            None
                        }
                    });
                    let output = session.digest(&raw, 10000, &Cancellation::new())?;
                    for (i, raw) in raw.iter().enumerate().take(4) {
                        assert_eq!(
                            output.expose(i).ok_or(Error::Invariant)?,
                            oracle(raw.as_ref().ok_or(Error::Invariant)?)?
                        );
                        cases += 1;
                    }
                    drop(output);
                    clear(&session);
                }
            }
        }
        assert_eq!(cases, 1024);
        println!("STRICT_KECCAK_BATCH: {route:?}; differential={cases}");
    }
    Ok(())
}
fn oracle(input: &Input<'_>) -> Result<Vec<u8>, Error> {
    use brynja_hash_sha3::{Fips202BitString, Fips202Output};
    let Algorithm::Keccak(algorithm, output_bits) = input.algorithm else {
        return Err(Error::InvalidInput);
    };
    fn canonical<'a>(b: &Bits<'a>) -> Result<Fips202BitString<'a>, Error> {
        Fips202BitString::new(b.bytes, b.valid_bits).map_err(|_| Error::InvalidInput)
    }
    let message = canonical(&input.message)?;
    let name = canonical(&input.name)?;
    let customization = canonical(&input.customization)?;
    let mut out = vec![0; input.algorithm.output_bytes()];
    let valid = if output_bits == 0 {
        0
    } else {
        u8::try_from((output_bits.saturating_sub(1) % 8).saturating_add(1))
            .map_err(|_| Error::Invariant)?
    };
    macro_rules! fixed {
        ($function:expr) => {
            out.copy_from_slice($function(message).map_err(|_| Error::Invariant)?.as_bytes())
        };
    }
    macro_rules! xof {
        ($function:expr) => {
            $function(
                message,
                Fips202Output::new(&mut out, valid).map_err(|_| Error::Invariant)?,
            )
            .map_err(|_| Error::Invariant)?
        };
    }
    macro_rules! custom {
        ($function:expr) => {
            $function(
                message,
                name,
                customization,
                Fips202Output::new(&mut out, valid).map_err(|_| Error::Invariant)?,
            )
            .map_err(|_| Error::Invariant)?
        };
    }
    match algorithm {
        keccak::Algorithm::Sha3_224 => fixed!(brynja_hash_sha3::sha3_224_bits),
        keccak::Algorithm::Sha3_256 => fixed!(brynja_hash_sha3::sha3_256_bits),
        keccak::Algorithm::Sha3_384 => fixed!(brynja_hash_sha3::sha3_384_bits),
        keccak::Algorithm::Sha3_512 => fixed!(brynja_hash_sha3::sha3_512_bits),
        keccak::Algorithm::Shake128 => xof!(brynja_hash_sha3::shake128_bits),
        keccak::Algorithm::Shake256 => xof!(brynja_hash_sha3::shake256_bits),
        keccak::Algorithm::Cshake128 => custom!(brynja_hash_sha3::cshake128_bits),
        keccak::Algorithm::Cshake256 => custom!(brynja_hash_sha3::cshake256_bits),
    }
    Ok(out)
}
