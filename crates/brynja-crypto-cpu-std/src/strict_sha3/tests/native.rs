use super::*;
use brynja_hash_sha3::{self as sha3, Fips202BitString, Fips202Output};

fn reference(
    algorithm: Algorithm,
    input: Fips202BitString<'_>,
    name: Fips202BitString<'_>,
    customization: Fips202BitString<'_>,
) -> Result<Vec<u8>, Error> {
    let mut output = vec![0; algorithm.output_bytes()];
    let valid = if output.is_empty() {
        0
    } else {
        let last = algorithm
            .output_bits()
            .checked_sub(1)
            .ok_or(Error::Invariant)?;
        u8::try_from((last % 8).checked_add(1).ok_or(Error::Invariant)?)
            .map_err(|_| Error::Invariant)?
    };
    macro_rules! fixed {
        ($function:ident) => {
            output.copy_from_slice(
                sha3::$function(input)
                    .map_err(|_| Error::Invariant)?
                    .as_bytes(),
            )
        };
    }
    match algorithm {
        Algorithm::Sha3_224 => fixed!(sha3_224_bits),
        Algorithm::Sha3_256 => fixed!(sha3_256_bits),
        Algorithm::Sha3_384 => fixed!(sha3_384_bits),
        Algorithm::Sha3_512 => fixed!(sha3_512_bits),
        Algorithm::Shake128(_) => sha3::shake128_bits(
            input,
            Fips202Output::new(&mut output, valid).map_err(|_| Error::InvalidBits)?,
        )
        .map_err(|_| Error::Invariant)?,
        Algorithm::Shake256(_) => sha3::shake256_bits(
            input,
            Fips202Output::new(&mut output, valid).map_err(|_| Error::InvalidBits)?,
        )
        .map_err(|_| Error::Invariant)?,
        Algorithm::Cshake128(_) => sha3::cshake128_bits(
            input,
            name,
            customization,
            Fips202Output::new(&mut output, valid).map_err(|_| Error::InvalidBits)?,
        )
        .map_err(|_| Error::Invariant)?,
        Algorithm::Cshake256(_) => sha3::cshake256_bits(
            input,
            name,
            customization,
            Fips202Output::new(&mut output, valid).map_err(|_| Error::InvalidBits)?,
        )
        .map_err(|_| Error::Invariant)?,
    }
    Ok(output)
}
fn canonical(bytes: &[u8], valid: u8) -> Result<Fips202BitString<'_>, Error> {
    Fips202BitString::new(bytes, valid).map_err(|_| Error::InvalidBits)
}
fn identities(bits: usize) -> [Algorithm; 8] {
    [
        Algorithm::Sha3_224,
        Algorithm::Sha3_256,
        Algorithm::Sha3_384,
        Algorithm::Sha3_512,
        Algorithm::Shake128(bits),
        Algorithm::Shake256(bits),
        Algorithm::Cshake128(bits),
        Algorithm::Cshake256(bits),
    ]
}

#[test]
fn all_identities_and_bit_tails_match_portable_across_rate_boundaries() -> Result<(), Error> {
    for algorithm in identities(1377) {
        let mut session = Session::new(algorithm, limits())?;
        for length in [
            0usize, 1, 71, 72, 73, 103, 104, 105, 135, 136, 137, 143, 144, 145, 167, 168, 169, 4097,
        ] {
            for valid in 1u8..=8 {
                let mut input: Vec<u8> = (0..=250).cycle().take(length).collect();
                if let Some(last) = input.last_mut() {
                    *last &= u8::MAX >> (8 - valid);
                }
                let valid = if input.is_empty() { 0 } else { valid };
                let expected = reference(
                    algorithm,
                    canonical(&input, valid)?,
                    canonical(&[], 0)?,
                    canonical(&[], 0)?,
                )?;
                let split = length.saturating_sub(1).min(33);
                let (head, tail) = input.split_at(split);
                let output = session.hash_chunks(
                    &[&[], head],
                    Bits {
                        bytes: tail,
                        valid_bits: valid,
                    },
                    &Cancellation::new(),
                )?;
                assert_eq!(output.algorithm(), algorithm);
                assert_eq!(output.expose(), expected);
                drop(output);
                assert!(session.output.as_bytes().iter().all(|b| *b == 0));
            }
        }
    }
    Ok(())
}

#[test]
fn xof_widths_and_customized_bit_prefixes_match_portable() -> Result<(), Error> {
    for bits in [
        0usize, 1, 7, 8, 9, 1087, 1088, 1344, 32767, 32768, 32769, 65539,
    ] {
        for algorithm in [
            Algorithm::Shake128(bits),
            Algorithm::Shake256(bits),
            Algorithm::Cshake128(bits),
            Algorithm::Cshake256(bits),
        ] {
            let mut session = Session::new(algorithm, limits())?;
            for valid in 0u8..=8 {
                let bytes: &[u8] = if valid == 0 { &[] } else { &[1] };
                let custom = if algorithm.customized() { bytes } else { &[] };
                let valid_custom = if custom.is_empty() { 0 } else { valid };
                let name = canonical(custom, valid_custom)?;
                let expected = reference(algorithm, canonical(b"abc", 8)?, name, name)?;
                let output = session.hash_customized_chunks(
                    &[b"a", &[], b"bc"],
                    Bits::empty(),
                    Bits {
                        bytes: custom,
                        valid_bits: valid_custom,
                    },
                    Bits {
                        bytes: custom,
                        valid_bits: valid_custom,
                    },
                    &Cancellation::new(),
                )?;
                assert_eq!(output.expose(), expected);
                assert_eq!(output.algorithm().output_bits(), bits);
            }
        }
    }
    Ok(())
}

#[test]
fn prefix_padding_boundaries_match_portable() -> Result<(), Error> {
    for algorithm in [Algorithm::Cshake128(1601), Algorithm::Cshake256(1601)] {
        let mut session = Session::new(algorithm, limits())?;
        for length in [1usize, 127, 128, 129, 135, 136, 137, 167, 168, 169, 256] {
            let name = vec![1; length];
            for valid in [1u8, 7, 8] {
                let expected = reference(
                    algorithm,
                    canonical(&[1], 1)?,
                    canonical(&name, valid)?,
                    canonical(&name, valid)?,
                )?;
                let output = session.hash_customized_chunks(
                    &[],
                    Bits {
                        bytes: &[1],
                        valid_bits: 1,
                    },
                    Bits {
                        bytes: &name,
                        valid_bits: valid,
                    },
                    Bits {
                        bytes: &name,
                        valid_bits: valid,
                    },
                    &Cancellation::new(),
                )?;
                assert_eq!(output.expose(), expected);
            }
        }
    }
    Ok(())
}

#[test]
fn errors_clear_forgotten_output_and_allow_reuse() -> Result<(), Error> {
    let mut bound = limits();
    bound.max_message_bits = 24;
    bound.max_chunks = 1;
    bound.max_customization_bits = 8;
    let mut session = Session::new(Algorithm::Cshake256(257), bound)?;
    for case in 0..8 {
        core::mem::forget(session.hash(b"abc")?);
        assert!(session.output.as_bytes().iter().any(|b| *b != 0));
        let cancelled = Cancellation::new();
        cancelled.cancel();
        let active = Cancellation::new();
        let empty = Bits::empty;
        let bad = || Bits {
            bytes: &[255],
            valid_bits: 1,
        };
        let result = match case {
            0 => session.hash(b"abcd"),
            1 => session.hash_chunks(&[], bad(), &active),
            2 => session.hash_chunks(&[b"a", b"b"], empty(), &active),
            3 => session.hash_chunks(&[], empty(), &cancelled),
            4 => session.hash_customized_chunks(&[], empty(), bad(), empty(), &active),
            5 => session.hash_customized_chunks(&[], empty(), empty(), bad(), &active),
            6 => session.hash_customized_chunks(&[], empty(), Bits::bytes(b"ab"), empty(), &active),
            _ => session.hash_chunks(
                &[],
                Bits {
                    bytes: &[],
                    valid_bits: 1,
                },
                &active,
            ),
        };
        assert!(result.is_err());
        drop(result);
        assert!(session.output.as_bytes().iter().all(|b| *b == 0));
        drop(session.hash(b"abc")?);
    }
    Ok(())
}

#[test]
fn cancel_and_post_write_unwind_clear_every_output_fragment() -> Result<(), Error> {
    for algorithm in [
        Algorithm::Sha3_256,
        Algorithm::Shake256(65539),
        Algorithm::Cshake128(65539),
    ] {
        let mut session = Session::new(algorithm, limits())?;
        // Fixed output has nine checkpoints; XOF variants have twelve.
        let checkpoints = if matches!(algorithm, Algorithm::Sha3_256) {
            9
        } else {
            12
        };
        for checkpoint in 0..checkpoints {
            session.fault = Fault::CancelAt(checkpoint);
            let result = session.hash_chunks(&[&[1; 8193]], Bits::empty(), &Cancellation::new());
            assert!(
                matches!(result, Err(Error::Cancelled)),
                "checkpoint {checkpoint}"
            );
            drop(result);
            assert!(session.output.as_bytes().iter().all(|b| *b == 0));
        }
        let writes = if matches!(algorithm, Algorithm::Sha3_256) {
            1
        } else {
            3
        };
        for write in 0..writes {
            session.fault = Fault::PanicAfterWrite(write);
            assert!(matches!(
                session.hash(b"abc"),
                Err(Error::Resource(
                    crate::protected_memory::Error::WorkerPanicked
                ))
            ));
            assert!(session.output.as_bytes().iter().all(|b| *b == 0));
        }
        session.fault = Fault::None;
        drop(session.hash(b"abc")?);
    }
    Ok(())
}

#[test]
fn real_protected_storage_exact_release_and_fail_closed_construction() -> Result<(), Error> {
    for algorithm in identities(65539) {
        let mut session = Session::new(algorithm, limits())?;
        session.fault = Fault::VerifyStorage;
        let output = session.hash(b"abc")?;
        verify_mapping(output.expose());
        let mut wrong = [0xa5; 1];
        assert_eq!(
            output.declassify(&mut wrong, PublicDeclassification::acknowledge()),
            Err(Error::OutputLength)
        );
        assert_eq!(wrong, [0xa5; 1]);
        assert!(session.output.as_bytes().iter().all(|b| *b == 0));
        let mut public = vec![0; algorithm.output_bytes()];
        session
            .hash(b"abc")?
            .declassify(&mut public, PublicDeclassification::acknowledge())?;
        assert_eq!(
            public,
            reference(
                algorithm,
                canonical(b"abc", 8)?,
                canonical(&[], 0)?,
                canonical(&[], 0)?
            )?
        );
        assert!(session.output.as_bytes().iter().all(|b| *b == 0));
    }
    let mut empty = Session::new(Algorithm::Shake128(0), limits())?;
    empty
        .hash(b"abc")?
        .declassify(&mut [], PublicDeclassification::acknowledge())?;
    assert_eq!(empty.output.as_bytes(), &[0]);
    for case in 0..4 {
        let mut bound = limits();
        match case {
            0 => bound.max_output_bits = 255,
            1 => bound.max_output_mapping_bytes = 32,
            2 => bound.stack_bytes = 65535,
            _ => bound.max_chunks = 0,
        }
        assert!(Session::new(Algorithm::Sha3_256, bound).is_err());
    }
    assert!(matches!(
        Session::new(Algorithm::Shake128(usize::MAX), limits()),
        Err(Error::WorkLimit)
    ));
    Ok(())
}
