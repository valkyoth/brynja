use super::*;
use brynja_crypto_cpu_std::macos_resident::Error as ResourceError;
use brynja_legacy_hmac::{BitString, Hmac};

// Keep this package's native reservations below ordinary per-process mlock limits.
static RESOURCES: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn session<A: Algorithm>(policy: TagPolicy) -> Result<Session<A>, Error> {
    Session::new(LegacyUse::acknowledge(), policy, limits())
}
fn cleared<A: Algorithm>(session: &Session<A>) {
    assert!(session.staging.as_bytes().iter().all(|b| *b == 0));
    assert!(session.output.as_bytes().iter().all(|b| *b == 0));
}
fn reference<A: Algorithm>(
    key: &[u8],
    message: &[u8],
    tail: Bits<'_>,
    bytes: usize,
) -> Result<Vec<u8>, Error> {
    let mut state =
        Hmac::<A>::with_tag_length(LegacyUse::acknowledge(), key, bytes).map_err(Error::Mac)?;
    state.update(message).map_err(Error::Mac)?;
    let mut output = vec![0; bytes];
    let _ = state
        .finalize_bits_tag(
            BitString::new(tail.bytes, tail.valid_bits).map_err(|_| Error::InvalidBits)?,
            &mut output,
        )
        .map_err(Error::Mac)?;
    Ok(output)
}
fn compare<A: Algorithm>() -> Result<(), Error> {
    for policy in [TagPolicy::Full, TagPolicy::Bytes(10)] {
        let mut owner = session::<A>(policy)?;
        for key_len in [0, 1, 63, 64, 65, 257] {
            let key = vec![0x5a; key_len];
            for len in [0, 55, 56, 63, 64, 65, 4097] {
                let message = vec![0x31; len];
                let expected = reference::<A>(&key, &message, Bits::empty(), owner.tag_bytes())?;

                owner.fault = Fault::None;
                let output = owner.authenticate(&key, &message)?;
                assert_eq!(output.expose(), expected);
                drop(output);
                cleared(&owner);
                owner.fault = Fault::None;
                let request = || Request {
                    key: &key,
                    chunks: &[],
                    tail: Bits::bytes(&message),
                };
                assert_eq!(
                    owner.verify(request(), &expected, &Cancellation::new()),
                    Ok(())
                );
                for index in 0..expected.len() {
                    let mut wrong = expected.clone();
                    *wrong.get_mut(index).ok_or(Error::Invariant)? ^= 1;
                    assert_eq!(
                        owner.verify(request(), &wrong, &Cancellation::new()),
                        Err(crate::VerificationError::Mismatch)
                    );
                }
                cleared(&owner);
            }
        }
    }
    Ok(())
}
#[test]
fn both_legacy_identities_match_and_storage_is_resident() -> Result<(), Error> {
    let _guard = RESOURCES.lock().map_err(|_| Error::Invariant)?;
    compare::<Sha1>()?;
    compare::<Md5>()
}
fn tails<A: Algorithm>() -> Result<(), Error> {
    let mut owner = session::<A>(TagPolicy::Full)?;
    for valid_bits in 1..=8 {
        for len in [1, 55, 56, 64, 65, 4097] {
            let mut bytes = vec![0x52; len];
            *bytes.last_mut().ok_or(Error::Invariant)? = 0x80;
            let tail = Bits {
                bytes: &bytes,
                valid_bits,
            };
            let expected = reference::<A>(&[0x51; 65], b"prefix", tail, owner.tag_bytes())?;
            let request = || Request {
                key: &[0x51; 65],
                chunks: &[b"pre", b"", b"fix"],
                tail,
            };
            assert_eq!(
                owner.compute(request(), &Cancellation::new())?.expose(),
                expected
            );
            assert_eq!(
                owner.verify(request(), &expected, &Cancellation::new()),
                Ok(())
            );
            cleared(&owner);
        }
    }
    let bad = Request {
        key: b"key",
        chunks: &[],
        tail: Bits {
            bytes: &[255],
            valid_bits: 3,
        },
    };
    assert!(matches!(
        owner.compute(bad, &Cancellation::new()),
        Err(Error::InvalidBits)
    ));
    cleared(&owner);
    Ok(())
}
#[test]
fn all_canonical_tail_widths_and_chunk_boundaries() -> Result<(), Error> {
    let _guard = RESOURCES.lock().map_err(|_| Error::Invariant)?;
    tails::<Sha1>()?;
    tails::<Md5>()
}
fn fault_case<A: Algorithm>() -> Result<(), Error> {
    let mut owner = session::<A>(TagPolicy::Full)?;
    let expected = reference::<A>(b"key", b"message", Bits::empty(), owner.tag_bytes())?;
    for verifying in [false, true] {
        let points = if verifying { 6 } else { 7 };
        for point in 0..points {
            for fault in [Fault::Cancel(point), Fault::Panic(point)] {
                owner.fault = fault;
                let request = Request {
                    key: b"key",
                    chunks: &[b"message"],
                    tail: Bits::empty(),
                };
                let result = if verifying {
                    owner
                        .verify(request, &expected, &Cancellation::new())
                        .map_err(|e| match e {
                            crate::VerificationError::Operation(error) => error,
                            crate::VerificationError::Mismatch => Error::Invariant,
                        })
                } else {
                    owner.compute(request, &Cancellation::new()).map(drop)
                };
                match fault {
                    Fault::Cancel(_) => assert_eq!(result, Err(Error::Cancelled)),
                    Fault::Panic(_) => {
                        assert_eq!(result, Err(Error::Resource(ResourceError::WorkerPanicked)))
                    }
                    _ => return Err(Error::Invariant),
                }
                cleared(&owner);
                owner.fault = Fault::None;
                assert_eq!(owner.authenticate(b"key", b"message")?.expose(), expected);
                cleared(&owner);
            }
        }
        // The very next point must not be reachable: pins the tested population.
        owner.fault = Fault::Panic(points);
        let request = Request {
            key: b"key",
            chunks: &[b"message"],
            tail: Bits::empty(),
        };
        if verifying {
            assert_eq!(
                owner.verify(request, &expected, &Cancellation::new()),
                Ok(())
            );
        } else {
            drop(owner.compute(request, &Cancellation::new())?);
        }
    }
    for (fault, error) in [
        (Fault::AfterWriteCancel, Error::Cancelled),
        (
            Fault::AfterWritePanic,
            Error::Resource(ResourceError::WorkerPanicked),
        ),
    ] {
        owner.fault = fault;
        assert!(matches!(owner.authenticate(b"key", b"message"), Err(e) if e == error));
        cleared(&owner);
        owner.fault = Fault::None;
        assert_eq!(owner.authenticate(b"key", b"message")?.expose(), expected);
    }
    cleared(&owner);
    Ok(())
}
#[test]
fn every_worker_checkpoint_and_post_write_failure_clear_and_reuse() -> Result<(), Error> {
    let _guard = RESOURCES.lock().map_err(|_| Error::Invariant)?;
    fault_case::<Sha1>()?;
    fault_case::<Md5>()
}
fn loans<A: Algorithm>() -> Result<(), Error> {
    let mut owner = session::<A>(TagPolicy::Bytes(10))?;
    let output = owner.authenticate(b"key", b"message")?;
    let mut public = [0xa5; 11];
    assert_eq!(
        output.declassify(&mut public, PublicDeclassification::acknowledge()),
        Err(Error::OutputLength)
    );
    assert_eq!(public, [0xa5; 11]);
    cleared(&owner);
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let output = owner.authenticate(b"key", b"message");
        assert!(output.is_ok());
        assert!(output.is_err(), "intentional loan consumer unwind");
    }));
    assert!(unwind.is_err());
    cleared(&owner);
    core::mem::forget(owner.authenticate(b"key", b"message")?);
    let cancel = Cancellation::new();
    cancel.cancel();
    assert!(matches!(
        owner.compute(
            Request {
                key: b"key",
                chunks: &[],
                tail: Bits::empty()
            },
            &cancel
        ),
        Err(Error::Cancelled)
    ));
    cleared(&owner);
    core::mem::forget(owner.authenticate(b"key", b"message")?);
    // Independently exercise the outer clearing contract; successful inner
    // SecretTag destruction already clears staging after ordinary completion.
    owner.staging.as_bytes_mut().fill(0x5a);
    owner.limits.max_key_bytes = 2;
    assert!(matches!(
        owner.authenticate(b"key", b"message"),
        Err(Error::WorkLimit)
    ));
    cleared(&owner);
    owner.limits = limits();
    let mut public = [0; 10];
    owner
        .authenticate(b"key", b"message")?
        .declassify(&mut public, PublicDeclassification::acknowledge())?;
    assert_eq!(
        public.as_slice(),
        reference::<A>(b"key", b"message", Bits::empty(), 10)?
    );
    cleared(&owner);
    Ok(())
}
#[test]
fn output_loan_forget_errors_and_explicit_release() -> Result<(), Error> {
    let _guard = RESOURCES.lock().map_err(|_| Error::Invariant)?;
    loans::<Sha1>()?;
    loans::<Md5>()
}
#[test]
fn resource_limits_reject_before_any_key_is_accepted() {
    let _guard = RESOURCES.lock();
    for (stack, stack_limit, buffer_limit) in [
        (0, 1048576, 65536),
        (262144, 1, 65536),
        (262144, 1048576, 1),
    ] {
        let mut limits = limits();
        limits.stack_bytes = stack;
        limits.max_stack_mapping_bytes = stack_limit;
        limits.max_buffer_mapping_bytes = buffer_limit;
        assert!(matches!(
            Session::<Sha1>::new(LegacyUse::acknowledge(), TagPolicy::Full, limits),
            Err(Error::Resource(_))
        ));
    }
}
