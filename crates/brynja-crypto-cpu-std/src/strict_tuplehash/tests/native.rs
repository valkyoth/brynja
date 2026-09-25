use super::*;
use brynja_hash_tuple::{self as tuple, Fips202BitString, Fips202Output};

fn canonical(bytes: &[u8], valid: u8) -> Result<Fips202BitString<'_>, Error> {
    Fips202BitString::new(bytes, valid).map_err(|_| Error::InvalidBits)
}
fn reference(
    algorithm: Algorithm,
    items: &[Bits<'_>],
    customization: Bits<'_>,
) -> Result<Vec<u8>, Error> {
    let customization = canonical(customization.bytes, customization.valid_bits)?;
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
    macro_rules! feed {
        ($state:ident) => {
            for item in items {
                $state
                    .push_item_bits(canonical(item.bytes, item.valid_bits)?)
                    .map_err(|_| Error::Invariant)?;
            }
        };
    }
    macro_rules! fixed {
        ($state:ident) => {{
            let mut state = tuple::$state::new_bits(customization).map_err(|_| Error::Invariant)?;
            feed!(state);
            state
                .finalize_bits(
                    Fips202Output::new(&mut output, valid).map_err(|_| Error::InvalidBits)?,
                )
                .map_err(|_| Error::Invariant)?;
        }};
    }
    macro_rules! xof {
        ($state:ident) => {{
            let mut state = tuple::$state::new_bits(customization).map_err(|_| Error::Invariant)?;
            feed!(state);
            state
                .finalize_xof()
                .map_err(|_| Error::Invariant)?
                .squeeze_final_bits(
                    Fips202Output::new(&mut output, valid).map_err(|_| Error::InvalidBits)?,
                )
                .map_err(|_| Error::Invariant)?;
        }};
    }
    match algorithm {
        Algorithm::TupleHash128(_) => fixed!(TupleHash128),
        Algorithm::TupleHash256(_) => fixed!(TupleHash256),
        Algorithm::TupleHashXof128(_) => xof!(TupleHashXof128),
        Algorithm::TupleHashXof256(_) => xof!(TupleHashXof256),
    }
    Ok(output)
}
fn identities(bits: usize) -> [Algorithm; 4] {
    [
        Algorithm::TupleHash128(bits),
        Algorithm::TupleHash256(bits),
        Algorithm::TupleHashXof128(bits),
        Algorithm::TupleHashXof256(bits),
    ]
}
fn cleared(session: &Session) {
    assert!(session.output.as_bytes().iter().all(|b| *b == 0));
    assert!(session.staging.as_bytes().iter().all(|b| *b == 0));
}

#[test]
fn tuple_boundaries_are_distinct_while_item_chunking_is_equivalent() -> Result<(), Error> {
    for algorithm in identities(256) {
        let mut session = Session::new(algorithm, limits())?;
        let variants: [&[Item<'_>]; 6] = [
            &[],
            &[Item::bytes(b"")],
            &[Item::bytes(b""), Item::bytes(b"")],
            &[Item::bytes(b"abc")],
            &[Item::bytes(b"ab"), Item::bytes(b"c")],
            &[Item::bytes(b"a"), Item::bytes(b"bc")],
        ];
        let mut outputs = Vec::new();
        for items in variants {
            outputs.push(session.hash(items, b"")?.expose().to_vec());
        }
        for (i, first) in outputs.iter().enumerate() {
            for (j, second) in outputs.iter().enumerate() {
                if i != j {
                    assert_ne!(first, second);
                }
            }
        }
        let chunked = [Item {
            chunks: &[b"a", &[], b"b"],
            tail: Bits::bytes(b"c"),
        }];
        assert_eq!(
            session.hash(&chunked, b"")?.expose(),
            outputs.get(3).ok_or(Error::Invariant)?
        );
    }
    Ok(())
}

#[test]
fn all_identities_bits_rates_and_streamed_items_match_portable() -> Result<(), Error> {
    for algorithm in identities(257) {
        let mut session = Session::new(algorithm, limits())?;
        for length in [0usize, 1, 31, 32, 33, 135, 136, 137, 167, 168, 169, 4097] {
            for valid in 1u8..=8 {
                let mut input: Vec<u8> = (0..=250).cycle().take(length).collect();
                if let Some(last) = input.last_mut() {
                    *last &= u8::MAX >> (8 - valid);
                }
                let valid = if length == 0 { 0 } else { valid };
                let expected = reference(
                    algorithm,
                    &[
                        Bits::empty(),
                        Bits {
                            bytes: &input,
                            valid_bits: valid,
                        },
                        Bits::bytes(b"end"),
                    ],
                    Bits::bytes(b"test"),
                )?;
                let split = length.saturating_sub(1).min(17);
                let (head, tail) = input.split_at(split);
                let items = [
                    Item::bytes(b""),
                    Item {
                        chunks: &[&[], head],
                        tail: Bits {
                            bytes: tail,
                            valid_bits: valid,
                        },
                    },
                    Item::bytes(b"end"),
                ];
                let output = session.hash(&items, b"test")?;
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
fn custom_bits_and_empty_partial_multifragment_output_match_portable() -> Result<(), Error> {
    for bits in [
        0usize, 1, 7, 8, 9, 1087, 1088, 1344, 32767, 32768, 32769, 65539,
    ] {
        for algorithm in identities(bits) {
            let mut session = Session::new(algorithm, limits())?;
            for valid in 0u8..=8 {
                let customization: &[u8] = if valid == 0 { &[] } else { &[1; 137] };
                let custom = || Bits {
                    bytes: customization,
                    valid_bits: valid,
                };
                let expected = reference(
                    algorithm,
                    &[Bits {
                        bytes: &[1; 33],
                        valid_bits: 1,
                    }],
                    custom(),
                )?;
                let items = [Item {
                    chunks: &[],
                    tail: Bits {
                        bytes: &[1; 33],
                        valid_bits: 1,
                    },
                }];
                let output = session.compute(&items, custom(), &Cancellation::new())?;
                assert_eq!(output.expose(), expected);
                drop(output);
                cleared(&session);
            }
        }
    }
    Ok(())
}

#[test]
fn rejection_clears_forgotten_output_and_does_not_poison_session() -> Result<(), Error> {
    let mut bound = limits();
    bound.max_items = 2;
    bound.max_chunks = 1;
    bound.max_input_bits = 24;
    bound.max_customization_bits = 8;
    let mut session = Session::new(Algorithm::TupleHash256(256), bound)?;
    for case in 0..8 {
        core::mem::forget(session.hash(&[Item::bytes(b"abc")], b"")?);
        let cancel = Cancellation::new();
        let result = match case {
            0 => session.hash(&[Item::bytes(b"abcd")], b""),
            1 => session.hash(&[Item::bytes(b""), Item::bytes(b""), Item::bytes(b"")], b""),
            2 => session.hash(
                &[Item {
                    chunks: &[&[], &[]],
                    tail: Bits::empty(),
                }],
                b"",
            ),
            3 => session.hash(&[], b"ab"),
            4 => session.compute(
                &[
                    Item::bytes(b"a"),
                    Item {
                        chunks: &[],
                        tail: Bits {
                            bytes: &[255],
                            valid_bits: 1,
                        },
                    },
                ],
                Bits::empty(),
                &cancel,
            ),
            5 => session.compute(
                &[],
                Bits {
                    bytes: &[255],
                    valid_bits: 1,
                },
                &cancel,
            ),
            6 => session.hash(
                &[Item {
                    chunks: &[],
                    tail: Bits {
                        bytes: &[],
                        valid_bits: 1,
                    },
                }],
                b"",
            ),
            _ => {
                cancel.cancel();
                session.compute(&[], Bits::empty(), &cancel)
            }
        };
        assert!(result.is_err());
        drop(result);
        cleared(&session);
        drop(session.hash(&[Item::bytes(b"abc")], b"")?);
    }
    Ok(())
}

#[test]
fn cancellation_unwind_and_wrong_item_length_cannot_produce_output() -> Result<(), Error> {
    for algorithm in identities(65539) {
        let mut session = Session::new(algorithm, limits())?;
        let items = [Item {
            chunks: &[&[1; 8193]],
            tail: Bits::empty(),
        }];
        let checkpoints = if algorithm.xof() { 14 } else { 11 };
        for checkpoint in 0..checkpoints {
            session.fault = Fault::CancelAt(checkpoint);
            assert!(
                matches!(
                    session.compute(&items, Bits::empty(), &Cancellation::new()),
                    Err(Error::Cancelled)
                ),
                "checkpoint {checkpoint}"
            );
            cleared(&session);
        }
        for fragment in 0..if algorithm.xof() { 3 } else { 1 } {
            session.fault = Fault::PanicAfterWrite(fragment);
            assert!(matches!(
                session.hash(&items, b""),
                Err(Error::Resource(
                    crate::protected_memory::Error::WorkerPanicked
                ))
            ));
            cleared(&session);
        }
        session.fault = Fault::WrongDeclaredLength;
        assert!(matches!(session.hash(&items, b""), Err(Error::Invariant)));
        cleared(&session);
        session.fault = Fault::None;
        drop(session.hash(&items, b"")?);
    }
    Ok(())
}

#[test]
fn resources_are_protected_and_public_release_is_explicit() -> Result<(), Error> {
    for algorithm in identities(257) {
        let mut session = Session::new(algorithm, limits())?;
        session.fault = Fault::VerifyStorage;
        let output = session.hash(&[Item::bytes(b"abc")], b"")?;
        let mut wrong = [0xa5; 32];
        assert_eq!(
            output.declassify(&mut wrong, PublicDeclassification::acknowledge()),
            Err(Error::OutputLength)
        );
        assert_eq!(wrong, [0xa5; 32]);
        cleared(&session);
        let mut public = [0; 33];
        session
            .hash(&[Item::bytes(b"abc")], b"")?
            .declassify(&mut public, PublicDeclassification::acknowledge())?;
        assert_eq!(
            public.as_slice(),
            reference(algorithm, &[Bits::bytes(b"abc")], Bits::empty())?
        );
        cleared(&session);
    }
    for algorithm in identities(0) {
        let mut bound = limits();
        bound.max_items = 0;
        bound.max_chunks = 0;
        bound.max_input_bits = 0;
        let mut session = Session::new(algorithm, bound)?;
        session
            .hash(&[], b"")?
            .declassify(&mut [], PublicDeclassification::acknowledge())?;
        cleared(&session);
    }
    for case in 0..3 {
        let mut bound = limits();
        match case {
            0 => bound.max_buffer_mapping_bytes = 32,
            1 => bound.stack_bytes = 65535,
            _ => bound.max_output_bits = 255,
        }
        assert!(Session::new(Algorithm::TupleHash256(256), bound).is_err());
    }
    Ok(())
}
