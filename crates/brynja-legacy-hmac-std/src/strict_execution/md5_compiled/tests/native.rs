use super::*;
use brynja_legacy_hmac::{BitString, Hmac};
static RESOURCES: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn session(bytes: usize) -> Result<Md5BatchSession, Error> {
    Md5BatchSession::new(LegacyUse::acknowledge(), TagPolicy::Bytes(bytes), limits())
}
fn cleared(s: &Md5BatchSession) {
    assert!(s.staging.as_bytes().iter().all(|b| *b == 0));
    assert!(s.output.as_bytes().iter().all(|b| *b == 0));
}
fn inputs() -> [Option<Md5BatchInput<'static>>; 8] {
    core::array::from_fn(|_| {
        Some(Md5BatchInput {
            key: &[0x5a; 80],
            message: Bits::bytes(&[0x31; 65]),
        })
    })
}
fn reusable(s: &mut Md5BatchSession) -> Result<(), Error> {
    s.fault = Fault::None;
    assert!(!s.is_quarantined());
    s.limits = limits();
    drop(s.compute(&inputs(), &Cancellation::new())?);
    cleared(s);
    Ok(())
}
fn terminal(s: &mut Md5BatchSession) {
    cleared(s);
    assert!(s.is_quarantined());
    s.fault = Fault::None;
    assert!(matches!(
        s.compute(&inputs(), &Cancellation::new()),
        Err(Error::Quarantined)
    ));
    cleared(s);
}
fn expected(inputs: &[Option<Md5BatchInput<'_>>; 8], bytes: usize) -> Result<[[u8; 16]; 8], Error> {
    let mut result = [[0; 16]; 8];
    for (input, row) in inputs.iter().zip(&mut result) {
        if let Some(input) = input {
            let state = Hmac::<Md5>::with_tag_length(LegacyUse::acknowledge(), input.key, bytes)
                .map_err(Error::Mac)?;
            let _ = state
                .finalize_bits_tag(
                    BitString::new(input.message.bytes, input.message.valid_bits)
                        .map_err(|_| Error::InvalidBits)?,
                    row.get_mut(..bytes).ok_or(Error::Invariant)?,
                )
                .map_err(Error::Mac)?;
        }
    }
    Ok(result)
}
fn compare(s: &mut Md5BatchSession, inputs: &[Option<Md5BatchInput<'_>>; 8]) -> Result<(), Error> {
    let expected = expected(inputs, s.bytes)?;
    let width = s.bytes;
    let tags = s.compute(inputs, &Cancellation::new())?;
    assert!(tags.expose(8).is_none());
    assert!(tags.expose(usize::MAX).is_none());
    for (lane, row) in expected.iter().enumerate() {
        let active = inputs.get(lane).is_some_and(Option::is_some);
        assert_eq!(
            tags.expose(lane),
            if active { row.get(..width) } else { None }
        );
    }
    // Compare full public output too: inactive rows and truncation padding zero.
    let mut public = [[0xa7; 16]; 8];
    tags.declassify(&mut public, PublicDeclassification::acknowledge())?;
    assert_eq!(public, expected);
    cleared(s);
    let candidates = core::array::from_fn(|lane| {
        if inputs.get(lane).is_some_and(Option::is_some) {
            expected.get(lane).and_then(|row| row.get(..s.bytes))
        } else {
            None
        }
    });
    assert!(s.verify(inputs, &candidates, &Cancellation::new())?);
    cleared(s);
    Ok(())
}
#[test]
fn all_slot_masks_and_canonical_bits_match_portable() -> Result<(), Error> {
    let _guard = RESOURCES.lock().map_err(|_| Error::Invariant)?;
    for bytes in [10, 16] {
        let mut s = session(bytes)?;
        assert_eq!(s.tag_bytes(), bytes);
        for mask in 0..256 {
            let inputs = core::array::from_fn(|lane| {
                if mask & (1 << lane) != 0 {
                    Some(Md5BatchInput {
                        key: &[0x5a; 65],
                        message: Bits::bytes(b"message"),
                    })
                } else {
                    None
                }
            });
            let eligible = inputs
                .chunks(s.vector_width())
                .any(|group| group.iter().all(Option::is_some));
            if eligible {
                compare(&mut s, &inputs)?;
            } else {
                assert!(matches!(
                    s.compute(&inputs, &Cancellation::new()),
                    Err(Error::Mac(brynja_legacy_hmac::Error::IneligibleWorkload))
                ));
                cleared(&s);
                assert!(!s.is_quarantined());
            }
        }
        for key_len in [0, 1, 63, 64, 65, 257] {
            let key = vec![0x5a; key_len];
            for len in [0, 1, 55, 56, 63, 64, 65, 4097] {
                let mut message = vec![0x31; len];
                if let Some(last) = message.last_mut() {
                    *last = 0x80;
                }
                for bits in 1..=8 {
                    let inputs = core::array::from_fn(|lane| {
                        Some(Md5BatchInput {
                            key: if lane % 2 == 0 { &key } else { b"short" },
                            message: Bits {
                                bytes: &message,
                                valid_bits: if len == 0 { 0 } else { bits },
                            },
                        })
                    });
                    compare(&mut s, &inputs)?;
                }
            }
        }
    }
    Ok(())
}
#[test]
fn every_active_tag_byte_is_compared_and_shapes_reject() -> Result<(), Error> {
    let _guard = RESOURCES.lock().map_err(|_| Error::Invariant)?;
    for bytes in 10..=16 {
        let mut s = session(bytes)?;
        let inputs = inputs();
        let expected = expected(&inputs, bytes)?;
        for lane in 0..8 {
            for byte in 0..bytes {
                let mut wrong = expected;
                *wrong
                    .get_mut(lane)
                    .and_then(|row| row.get_mut(byte))
                    .ok_or(Error::Invariant)? ^= 1;
                let candidates = wrong.each_ref().map(|row| row.get(..bytes));
                assert!(!s.verify(&inputs, &candidates, &Cancellation::new())?);
            }
        }
        assert_eq!(
            s.verify(&inputs, &[None; 8], &Cancellation::new()),
            Err(Error::OutputLength)
        );
        cleared(&s);
        reusable(&mut s)?;
    }
    Ok(())
}
#[test]
fn all_control_failures_preserve_or_quarantine_correctly() -> Result<(), Error> {
    let _guard = RESOURCES.lock().map_err(|_| Error::Invariant)?;
    // Single long key selects scalar normalization; all long keys select SIMD.
    for scalar_normalization in [false, true] {
        let mut inputs = inputs();
        if scalar_normalization {
            for input in inputs.iter_mut().skip(1).flatten() {
                input.key = b"short";
            }
        }
        for verifying in [false, true] {
            let candidates = [Some(&[0u8; 16][..]); 8];
            let invoke = |s: &mut Md5BatchSession, c: &Cancellation| {
                s.execute(&inputs, if verifying { Some(&candidates) } else { None }, c)
            };
            let mut s = session(16)?;
            assert!(invoke(&mut s, &Cancellation::new()).is_ok());
            let points = OBSERVED.load(Ordering::SeqCst);
            assert!(points > 8);
            for point in 0..points {
                s.fault = Fault::Cancel(point);
                assert!(matches!(
                    invoke(&mut s, &Cancellation::new()),
                    Err(Error::Cancelled | Error::Mac(brynja_legacy_hmac::Error::Cancelled))
                ));
                cleared(&s);
                reusable(&mut s)?;
                s.fault = Fault::Revoke(point);
                assert_eq!(
                    invoke(&mut s, &Cancellation::new()),
                    Err(Error::Mac(brynja_legacy_hmac::Error::ExecutionFailed))
                );
                terminal(&mut s);
                s = session(16)?;
                s.fault = Fault::Panic(point);
                assert_eq!(
                    invoke(&mut s, &Cancellation::new()),
                    Err(Error::Resource(protected_memory::Error::WorkerPanicked))
                );
                terminal(&mut s);
                s = session(16)?;
            }
            for fault in [Fault::WrongReport, Fault::WrongShape] {
                s.fault = fault;
                assert_eq!(invoke(&mut s, &Cancellation::new()), Err(Error::Invariant));
                terminal(&mut s);
                s = session(16)?;
            }
            let mut rejected = false;
            let mut completed = false;
            for budget in 0..=64 {
                s.limits.max_compressions = budget;
                match invoke(&mut s, &Cancellation::new()) {
                    Err(Error::Mac(brynja_legacy_hmac::Error::WorkLimit)) => rejected = true,
                    Ok(_) => completed = true,
                    _ => return Err(Error::Invariant),
                }
                s.output.clear(); // Successful internal execute has no public loan.
                cleared(&s);
                reusable(&mut s)?;
            }
            assert!(rejected && completed);
        }
    }
    Ok(())
}
#[test]
fn loans_admission_and_explicit_quarantine_clear_all_slots() -> Result<(), Error> {
    let _guard = RESOURCES.lock().map_err(|_| Error::Invariant)?;
    let mut s = session(16)?;
    s.fault = Fault::Observe;
    core::mem::forget(s.compute(&inputs(), &Cancellation::new())?);
    s.fault = Fault::None;
    s.staging.as_bytes_mut().fill(0xa7);
    assert_eq!(
        s.verify(&inputs(), &[Some(&[0; 15]); 8], &Cancellation::new()),
        Err(Error::OutputLength)
    );
    cleared(&s);
    let mut bad = inputs();
    bad.get_mut(0)
        .and_then(Option::as_mut)
        .ok_or(Error::Invariant)?
        .message = Bits {
        bytes: &[255],
        valid_bits: 3,
    };
    assert!(matches!(
        s.compute(&bad, &Cancellation::new()),
        Err(Error::InvalidBits)
    ));
    cleared(&s);
    reusable(&mut s)?;
    s.limits.max_key_bytes = 0;
    assert!(matches!(
        s.compute(&inputs(), &Cancellation::new()),
        Err(Error::WorkLimit)
    ));
    cleared(&s);
    reusable(&mut s)?;
    core::mem::forget(s.compute(&inputs(), &Cancellation::new())?);
    s.staging.as_bytes_mut().fill(0xa7);
    s.quarantine();
    terminal(&mut s);
    let mut s = session(16)?;
    core::mem::forget(s.compute(&inputs(), &Cancellation::new())?);
    let cancelled = Cancellation::new();
    cancelled.cancel();
    s.fault = Fault::Panic(0);
    assert!(matches!(
        s.compute(&inputs(), &cancelled),
        Err(Error::Cancelled)
    ));
    cleared(&s);
    reusable(&mut s)?;
    drop(s);
    let mut s = session(16)?;
    s.backend = if s.backend == Md5Backend::X86Avx2 {
        Md5Backend::Aarch64Neon
    } else {
        Md5Backend::X86Avx2
    };
    assert!(matches!(
        s.compute(&inputs(), &Cancellation::new()),
        Err(Error::Invariant)
    ));
    assert_eq!(
        OBSERVED.load(Ordering::SeqCst),
        0,
        "wrong backend reached key-processing checkpoints"
    );
    terminal(&mut s);
    for (stack, stack_limit, buffer_limit) in [
        (0, 1048576, 65536),
        (262144, 1, 65536),
        (262144, 1048576, 1),
    ] {
        let mut bound = limits();
        bound.stack_bytes = stack;
        bound.max_stack_mapping_bytes = stack_limit;
        bound.max_buffer_mapping_bytes = buffer_limit;
        assert!(matches!(
            Md5BatchSession::new(LegacyUse::acknowledge(), TagPolicy::Full, bound),
            Err(Error::Resource(_))
        ));
    }
    Ok(())
}
