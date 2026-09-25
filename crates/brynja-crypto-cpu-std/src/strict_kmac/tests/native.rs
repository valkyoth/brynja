use super::*;
use brynja_mac_kmac::{self as kmac, Fips202BitString};

fn canonical(bits: Bits<'_>) -> Result<Fips202BitString<'_>, Error> {
    Fips202BitString::new(bits.bytes, bits.valid_bits).map_err(|_| Error::InvalidBits)
}
fn reference(
    algorithm: Algorithm,
    key: Bits<'_>,
    message: Bits<'_>,
    customization: Bits<'_>,
) -> Result<Vec<u8>, Error> {
    let key = canonical(key)?;
    let message = canonical(message)?;
    let customization = canonical(customization)?;
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
        ($state:ident) => {{
            let state = kmac::$state::new_bits(key, customization).map_err(|_| Error::Invariant)?;
            let _tag = state
                .finalize_tag_bits(message, &mut output, valid)
                .map_err(|_| Error::Invariant)?;
        }};
    }
    macro_rules! xof {
        ($state:ident) => {
            kmac::$state::new_bits(key, customization)
                .map_err(|_| Error::Invariant)?
                .finalize_bits_xof(message)
                .map_err(|_| Error::Invariant)?
                .squeeze_final_bits_public(
                    kmac::Fips202Output::new(&mut output, valid).map_err(|_| Error::InvalidBits)?,
                    PublicDeclassification::acknowledge(),
                )
                .map_err(|_| Error::Invariant)?
        };
    }
    match algorithm {
        Algorithm::Kmac128(_) => fixed!(Kmac128),
        Algorithm::Kmac256(_) => fixed!(Kmac256),
        Algorithm::KmacXof128(_) => xof!(KmacXof128),
        Algorithm::KmacXof256(_) => xof!(KmacXof256),
    }
    Ok(output)
}
fn request<'a>(chunks: &'a [&'a [u8]]) -> Request<'a> {
    Request {
        key: Bits::bytes(&[0x42; 32]),
        customization: Bits::empty(),
        chunks,
        tail: Bits::empty(),
    }
}
fn identities(bits: usize) -> [Algorithm; 4] {
    [
        Algorithm::Kmac128(bits),
        Algorithm::Kmac256(bits),
        Algorithm::KmacXof128(bits),
        Algorithm::KmacXof256(bits),
    ]
}
fn cleared(session: &Session) {
    assert!(session.output.as_bytes().iter().all(|b| *b == 0));
    assert!(session.staging.as_bytes().iter().all(|b| *b == 0));
}

#[test]
fn all_identities_rate_boundaries_and_bit_inputs_match_portable() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    for algorithm in identities(257) {
        let mut session = Session::new(algorithm, limits())?;
        for length in [0usize, 1, 135, 136, 137, 167, 168, 169, 4097] {
            for valid in 1u8..=8 {
                let mut input: Vec<u8> = (0..=250).cycle().take(length).collect();
                if let Some(last) = input.last_mut() {
                    *last &= u8::MAX >> (8 - valid);
                }
                let valid = if length == 0 { 0 } else { valid };
                let expected = reference(
                    algorithm,
                    Bits::bytes(&[0x42; 32]),
                    Bits {
                        bytes: &input,
                        valid_bits: valid,
                    },
                    Bits::bytes(b"test"),
                )?;
                let split = length.saturating_sub(1).min(17);
                let (head, tail) = input.split_at(split);
                let output = session.compute(
                    Request {
                        key: Bits::bytes(&[0x42; 32]),
                        customization: Bits::bytes(b"test"),
                        chunks: &[&[], head],
                        tail: Bits {
                            bytes: tail,
                            valid_bits: valid,
                        },
                    },
                    &Cancellation::new(),
                )?;
                assert_eq!(output.algorithm(), algorithm);
                assert_eq!(output.expose(), expected);
                drop(output);
                cleared(&session);
            }
        }
    }
    Ok(())
}

#[test]
fn bit_keys_prefixes_and_multifragment_outputs_match_portable() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    for algorithm in identities(65539) {
        let mut session = Session::new(algorithm, limits())?;
        for key_len in [33usize, 135, 136, 167, 168, 169] {
            let key = vec![1; key_len];
            for valid in [1u8, 7, 8] {
                let customization = vec![1; 137];
                let expected = reference(
                    algorithm,
                    Bits {
                        bytes: &key,
                        valid_bits: valid,
                    },
                    Bits {
                        bytes: &[1],
                        valid_bits: 1,
                    },
                    Bits {
                        bytes: &customization,
                        valid_bits: valid,
                    },
                )?;
                let output = session.compute(
                    Request {
                        key: Bits {
                            bytes: &key,
                            valid_bits: valid,
                        },
                        customization: Bits {
                            bytes: &customization,
                            valid_bits: valid,
                        },
                        chunks: &[],
                        tail: Bits {
                            bytes: &[1],
                            valid_bits: 1,
                        },
                    },
                    &Cancellation::new(),
                )?;
                assert_eq!(output.expose(), expected);
                drop(output);
                cleared(&session);
            }
        }
    }
    for bits in [0usize, 1, 7, 8, 9, 1087, 1088, 1344, 32767, 32768, 32769] {
        for algorithm in [Algorithm::KmacXof128(bits), Algorithm::KmacXof256(bits)] {
            let mut session = Session::new(algorithm, limits())?;
            let output = session.authenticate(&[1; 32], b"abc", b"")?;
            assert_eq!(
                output.expose(),
                reference(
                    algorithm,
                    Bits::bytes(&[1; 32]),
                    Bits::bytes(b"abc"),
                    Bits::empty()
                )?
            );
            assert_eq!(output.algorithm().output_bits(), bits);
        }
    }
    Ok(())
}

#[test]
fn verification_is_exact_constant_work_and_clears_output() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    for algorithm in identities(65539) {
        let mut session = Session::new(algorithm, limits())?;
        let tag = session
            .authenticate(&[0x42; 32], b"abc", b"")?
            .expose()
            .to_vec();
        session.fault = Fault::VerifyCompared(tag.len());
        assert!(session.verify(
            request(&[b"abc"]),
            Bits {
                bytes: &tag,
                valid_bits: 3
            },
            &Cancellation::new()
        )?);
        cleared(&session);
        for position in [0, 4095, 4096, tag.len().saturating_sub(1)] {
            let mut wrong = tag.clone();
            *wrong.get_mut(position).ok_or(Error::Invariant)? ^= 1;
            assert!(!session.verify(
                request(&[b"abc"]),
                Bits {
                    bytes: &wrong,
                    valid_bits: 3
                },
                &Cancellation::new()
            )?);
            cleared(&session);
        }
        let mut noncanonical = tag.clone();
        *noncanonical.last_mut().ok_or(Error::Invariant)? |= 0x80;
        assert_eq!(
            session.verify(
                request(&[b"abc"]),
                Bits {
                    bytes: &noncanonical,
                    valid_bits: 3
                },
                &Cancellation::new()
            ),
            Err(Error::InvalidBits)
        );
        cleared(&session);
        assert_eq!(
            session.verify(
                request(&[b"abc"]),
                Bits {
                    bytes: &tag,
                    valid_bits: 2
                },
                &Cancellation::new()
            ),
            Err(Error::OutputLength)
        );
        cleared(&session);
    }
    let mut empty = Session::new(Algorithm::KmacXof128(0), limits())?;
    assert_eq!(
        empty.verify(request(&[]), Bits::empty(), &Cancellation::new()),
        Err(Error::TagTooShort)
    );
    empty
        .authenticate(&[1; 32], b"", b"")?
        .declassify(&mut [], PublicDeclassification::acknowledge())?;
    cleared(&empty);
    Ok(())
}

#[test]
fn invalid_requests_clear_previous_forgotten_loans_and_allow_reuse() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    let mut bound = limits();
    bound.max_chunks = 1;
    bound.max_message_bits = 24;
    bound.max_setup_bits = 272;
    let mut session = Session::new(Algorithm::Kmac256(256), bound)?;
    for case in 0..8 {
        core::mem::forget(session.authenticate(&[0x42; 32], b"abc", b"")?);
        let mut r = request(&[b"abc"]);
        let cancel = Cancellation::new();
        match case {
            0 => r.key = Bits::bytes(&[1; 31]),
            1 => {
                r.key = Bits {
                    bytes: &[255; 33],
                    valid_bits: 1,
                }
            }
            2 => {
                r.customization = Bits {
                    bytes: &[255],
                    valid_bits: 1,
                }
            }
            3 => r.customization = Bits::bytes(b"abc"),
            4 => r.chunks = &[b"a", b"b"],
            5 => r.chunks = &[b"abcd"],
            6 => {
                r.tail = Bits {
                    bytes: &[],
                    valid_bits: 1,
                }
            }
            _ => cancel.cancel(),
        }
        assert!(session.compute(r, &cancel).is_err());
        cleared(&session);
        drop(session.authenticate(&[0x42; 32], b"abc", b"")?);
    }
    for algorithm in [Algorithm::Kmac128(127), Algorithm::Kmac256(255)] {
        assert!(matches!(
            Session::new(algorithm, limits()),
            Err(Error::TagTooShort)
        ));
    }
    Ok(())
}

#[test]
fn cancellation_unwind_and_verification_cleanup_cover_all_fragments() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    for algorithm in identities(65539) {
        let mut session = Session::new(algorithm, limits())?;
        let tag = session
            .authenticate(&[0x42; 32], &[1; 8193], b"")?
            .expose()
            .to_vec();
        let checkpoints = if algorithm.xof() { 16 } else { 13 };
        for checkpoint in 0..checkpoints {
            session.fault = Fault::CancelAt(checkpoint);
            assert_eq!(
                session.verify(
                    request(&[&[1; 8193]]),
                    Bits {
                        bytes: &tag,
                        valid_bits: 3
                    },
                    &Cancellation::new()
                ),
                Err(Error::Cancelled),
                "checkpoint {checkpoint}"
            );
            cleared(&session);
        }
        for fragment in 0..if algorithm.xof() { 3 } else { 1 } {
            session.fault = Fault::PanicAfterWrite(fragment);
            assert!(matches!(
                session.authenticate(&[0x42; 32], b"abc", b""),
                Err(Error::Resource(
                    crate::protected_memory::Error::WorkerPanicked
                ))
            ));
            cleared(&session);
        }
        session.fault = Fault::None;
        drop(session.authenticate(&[0x42; 32], b"abc", b"")?);
    }
    Ok(())
}

#[test]
fn actual_protection_and_explicit_public_release() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    for algorithm in identities(257) {
        let mut session = Session::new(algorithm, limits())?;
        session.fault = Fault::VerifyStorage;
        let output = session.authenticate(&[0x42; 32], b"abc", b"")?;
        let mut wrong = [0xa5; 32];
        assert_eq!(
            output.declassify(&mut wrong, PublicDeclassification::acknowledge()),
            Err(Error::OutputLength)
        );
        assert_eq!(wrong, [0xa5; 32]);
        cleared(&session);
        let mut public = [0; 33];
        session
            .authenticate(&[0x42; 32], b"abc", b"")?
            .declassify(&mut public, PublicDeclassification::acknowledge())?;
        cleared(&session);
        assert!(session.verify(
            request(&[b"abc"]),
            Bits {
                bytes: &public,
                valid_bits: 1
            },
            &Cancellation::new()
        )?);
        cleared(&session);
    }
    for case in 0..4 {
        let mut bound = limits();
        match case {
            0 => bound.max_buffer_mapping_bytes = 32,
            1 => bound.stack_bytes = 65535,
            2 => bound.max_output_bits = 255,
            _ => bound.max_chunks = 0,
        }
        assert!(Session::new(Algorithm::Kmac256(256), bound).is_err());
    }
    Ok(())
}

#[test]
fn production_key_strength_is_not_weakened_by_conformance_features() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    for algorithm in identities(256) {
        let mut session = Session::new(algorithm, limits())?;
        for bits in [0usize, 127, 128, 129, 255, 256, 257] {
            let key = vec![0; bits.div_ceil(8)];
            let valid = if bits == 0 {
                0
            } else {
                let last = bits.checked_sub(1).ok_or(Error::Invariant)?;
                u8::try_from((last % 8).checked_add(1).ok_or(Error::Invariant)?)
                    .map_err(|_| Error::Invariant)?
            };
            let mut r = request(&[b"abc"]);
            r.key = Bits {
                bytes: &key,
                valid_bits: valid,
            };
            let result = session.compute(r, &Cancellation::new());
            if bits < algorithm.strength() {
                assert!(matches!(result, Err(Error::KeyTooShort)));
            } else {
                assert!(result.is_ok());
            }
            drop(result);
            cleared(&session);
        }
    }
    Ok(())
}
