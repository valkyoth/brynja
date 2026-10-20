use super::*;
use brynja_mac_hmac as mac;

fn cleared<A: Algorithm>(session: &Session<A>) {
    assert!(session.staging.bytes().iter().all(|b| *b == 0));
    assert!(session.output.bytes().iter().all(|b| *b == 0));
}
fn compare<A: Algorithm>() -> Result<(), Error> {
    for policy in [TagPolicy::Full, TagPolicy::Bytes(16)] {
        let mut session = Session::<A>::new(policy, limits())?;
        verify_resources(&session)?;
        session.fault = Fault::Observe;
        for key_len in [
            0,
            1,
            A::BLOCK_BYTES,
            A::BLOCK_BYTES.checked_add(1).ok_or(Error::Invariant)?,
            257,
        ] {
            let key = vec![0x5a; key_len];
            let message = vec![0x31; 8193];
            let bits = session.tag_bits();
            let mut expected = vec![0; bits.div_ceil(8)];
            let mut reference = match policy {
                TagPolicy::Full => mac::Hmac::<A>::new(&key),
                TagPolicy::Bytes(bytes) => mac::Hmac::<A>::with_tag_length(&key, bytes),
            }
            .map_err(Error::Mac)?;
            reference.update(&message).map_err(Error::Mac)?;
            let tag = reference.finalize_tag(&mut expected).map_err(Error::Mac)?;
            assert_eq!(tag.bit_len(), bits);
            let output = session.authenticate(&key, &message)?;
            assert_eq!(output.bit_len(), bits);
            assert_eq!(output.expose(), expected);
            drop(output);
            cleared(&session);
            let request = || Request {
                key: &key,
                chunks: &[b""],
                tail: Bits::bytes(&message),
            };
            assert!(session.verify(request(), &expected, &Cancellation::new())?);
            cleared(&session);
            for index in [0, expected.len().checked_sub(1).ok_or(Error::Invariant)?] {
                let mut wrong = expected.clone();
                *wrong.get_mut(index).ok_or(Error::Invariant)? ^= 1;
                assert!(!session.verify(request(), &wrong, &Cancellation::new())?);
                cleared(&session);
            }
        }
    }
    Ok(())
}

#[test]
fn all_identities_match_portable_and_storage_is_resident() -> Result<(), Error> {
    let _resources = crate::macos_resident::hmac::tests::resources();
    compare::<Sha224>()?;
    compare::<Sha256>()?;
    compare::<Sha384>()?;
    compare::<Sha512>()?;
    compare::<Sha512_224>()?;
    compare::<Sha512_256>()?;
    compare::<Sha512T<129>>()?;
    compare::<Sha512T<511>>()?;
    compare::<Sha3_224>()?;
    compare::<Sha3_256>()?;
    compare::<Sha3_384>()?;
    compare::<Sha3_512>()?;
    Ok(())
}

fn bit_case<A: Algorithm>(last: u8) -> Result<(), Error> {
    let mut session = Session::<A>::new(TagPolicy::Full, limits())?;
    let key = [0x51; 257];
    for length in [1, 64, 65, 4097] {
        let mut tail = vec![0x51; length];
        *tail.last_mut().ok_or(Error::Invariant)? = last;
        let input = Bits {
            bytes: &tail,
            valid_bits: 3,
        };
        let mut state = mac::Hmac::<A>::new(&key).map_err(Error::Mac)?;
        state.update(b"prefix").map_err(Error::Mac)?;
        let mut expected = vec![0; A::TAG_BYTES];
        let _ = state
            .finalize_bits_tag(A::tail(input)?, &mut expected)
            .map_err(Error::Mac)?;
        let request = || Request {
            key: &key,
            chunks: &[b"prefix"],
            tail: input,
        };
        let output = session.compute(request(), &Cancellation::new())?;
        assert_eq!(output.expose(), expected);
        drop(output);
        assert!(session.verify(request(), &expected, &Cancellation::new())?);
        cleared(&session);
    }
    let bad = || Request {
        key: &key,
        chunks: &[],
        tail: Bits {
            bytes: &[255],
            valid_bits: 3,
        },
    };
    assert!(matches!(
        session.compute(bad(), &Cancellation::new()),
        Err(Error::InvalidBits)
    ));
    cleared(&session);
    Ok(())
}
#[test]
fn canonical_bit_tails_chunk_without_rounding() -> Result<(), Error> {
    let _resources = crate::macos_resident::hmac::tests::resources();
    bit_case::<Sha256>(0xa0)?;
    bit_case::<Sha512T<129>>(0xa0)?;
    bit_case::<Sha3_256>(5)?;
    Ok(())
}

#[test]
fn cancellation_unwind_and_post_write_failure_clear_and_reuse() -> Result<(), Error> {
    let _resources = crate::macos_resident::hmac::tests::resources();
    let mut session = Session::<Sha256>::new(TagPolicy::Full, limits())?;
    for step in 0..7 {
        for fault in [Fault::Cancel(step), Fault::Panic(step)] {
            session.fault = fault;
            assert!(session.authenticate(b"key", b"message").is_err());
            cleared(&session);
            session.fault = Fault::None;
            drop(session.authenticate(b"key", b"message")?);
            cleared(&session);
        }
    }
    session.fault = Fault::AfterWrite;
    assert!(matches!(
        session.authenticate(b"key", b"message"),
        Err(Error::Resource(
            crate::macos_resident::Error::WorkerPanicked
        ))
    ));
    cleared(&session);
    session.fault = Fault::None;
    drop(session.authenticate(b"key", b"message")?);
    let tag = session.authenticate(b"key", b"message")?.expose().to_vec();
    for step in 0..6 {
        for fault in [Fault::Cancel(step), Fault::Panic(step)] {
            session.fault = fault;
            assert!(
                session
                    .verify(
                        Request {
                            key: b"key",
                            chunks: &[b"message"],
                            tail: Bits::empty()
                        },
                        &tag,
                        &Cancellation::new(),
                    )
                    .is_err()
            );
            cleared(&session);
        }
    }
    session.fault = Fault::None;
    assert!(session.verify(
        Request {
            key: b"key",
            chunks: &[b"message"],
            tail: Bits::empty()
        },
        &tag,
        &Cancellation::new(),
    )?);
    Ok(())
}

#[test]
fn output_loans_forget_and_errors_preserve_public_bytes() -> Result<(), Error> {
    let _resources = crate::macos_resident::hmac::tests::resources();
    let mut session = Session::<Sha256>::new(TagPolicy::Bytes(16), limits())?;
    let output = session.authenticate(b"key", b"message")?;
    let mut public = [0xa5; 17];
    assert_eq!(
        output.declassify(&mut public, PublicDeclassification::acknowledge()),
        Err(Error::OutputLength)
    );
    assert_eq!(public, [0xa5; 17]);
    cleared(&session);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let output = session.authenticate(b"key", b"message");
        assert!(output.is_ok());
        assert!(output.is_err(), "intentional output consumer unwind");
    }));
    assert!(unwound.is_err());
    cleared(&session);
    core::mem::forget(session.authenticate(b"key", b"message")?);
    let cancelled = Cancellation::new();
    cancelled.cancel();
    assert!(matches!(
        session.compute(
            Request {
                key: b"key",
                chunks: &[],
                tail: Bits::empty()
            },
            &cancelled
        ),
        Err(Error::Cancelled)
    ));
    cleared(&session);
    let output = session.authenticate(b"key", b"message")?;
    let mut public = [0; 16];
    output.declassify(&mut public, PublicDeclassification::acknowledge())?;
    cleared(&session);
    assert!(
        mac::Hmac::<Sha256>::with_tag_length(b"key", 16)
            .map_err(Error::Mac)?
            .verify_bits(
                mac::Sha2BitString::new(b"message", 8).map_err(|_| Error::InvalidBits)?,
                &public
            )
            .map_err(Error::Mac)?
            .expose_public()
    );
    Ok(())
}

#[test]
fn budgets_and_partial_tag_comparison_fail_closed() -> Result<(), Error> {
    let _resources = crate::macos_resident::hmac::tests::resources();
    for bytes in [0, 1, 65535] {
        let mut invalid = limits();
        invalid.stack_bytes = bytes;
        assert!(matches!(
            Session::<Sha256>::new(TagPolicy::Full, invalid),
            Err(Error::Resource(crate::macos_resident::Error::InvalidSize))
        ));
    }
    let mut invalid = limits();
    invalid.max_chunks = 0;
    assert!(matches!(
        Session::<Sha256>::new(TagPolicy::Full, invalid),
        Err(Error::InvalidLimits)
    ));
    invalid = limits();
    invalid.max_stack_mapping_bytes = 1;
    assert!(Session::<Sha256>::new(TagPolicy::Full, invalid).is_err());
    let mut bound = limits();
    bound.max_key_bytes = 3;
    bound.max_message_bits = 24;
    bound.max_chunks = 1;
    let mut session = Session::<Sha512T<129>>::new(TagPolicy::Full, bound)?;
    let tag = session.authenticate(b"key", b"abc")?.expose().to_vec();
    assert_eq!(tag.get(16).ok_or(Error::Invariant)? & 127, 0);
    for request in [
        Request {
            key: b"long",
            chunks: &[b"abc"],
            tail: Bits::empty(),
        },
        Request {
            key: b"key",
            chunks: &[b"abcd"],
            tail: Bits::empty(),
        },
        Request {
            key: b"key",
            chunks: &[b"", b""],
            tail: Bits::empty(),
        },
    ] {
        assert!(matches!(
            session.compute(request, &Cancellation::new()),
            Err(Error::WorkLimit)
        ));
        cleared(&session);
    }
    let mut wrong = tag;
    *wrong.get_mut(16).ok_or(Error::Invariant)? |= 1;
    assert!(!session.verify(
        Request {
            key: b"key",
            chunks: &[b"abc"],
            tail: Bits::empty()
        },
        &wrong,
        &Cancellation::new()
    )?);
    cleared(&session);
    bound.max_buffer_mapping_bytes = 1;
    assert!(Session::<Sha256>::new(TagPolicy::Full, bound).is_err());
    Ok(())
}
