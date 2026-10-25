use super::super::super::tests::Fault as WorkerFault;
use super::*;
use brynja_legacy_hmac::{BitString, Hmac};
static RESOURCES: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn session(bytes: usize) -> Result<Sha1CompiledSession, Error> {
    Sha1CompiledSession::new(LegacyUse::acknowledge(), TagPolicy::Bytes(bytes), limits())
}
fn cleared(s: &Sha1CompiledSession) {
    assert!(s.inner.staging.as_bytes().iter().all(|b| *b == 0));
    assert!(s.inner.output.as_bytes().iter().all(|b| *b == 0));
}
fn request() -> Request<'static> {
    Request {
        key: b"key",
        chunks: &[b"message"],
        tail: Bits::empty(),
    }
}
fn reusable(s: &mut Sha1CompiledSession) -> Result<(), Error> {
    s.inner.fault = WorkerFault::None;
    s.fault = Fault::None;
    assert!(!s.is_quarantined());
    let output = s.authenticate(b"key", b"message")?;
    assert!(output.expose().iter().any(|b| *b != 0));
    drop(output);
    cleared(s);
    Ok(())
}
fn terminal(s: &mut Sha1CompiledSession) {
    cleared(s);
    assert!(s.is_quarantined());
    s.inner.fault = WorkerFault::None;
    s.fault = Fault::None;
    assert!(matches!(
        s.authenticate(b"key", b"message"),
        Err(Error::Quarantined)
    ));
    cleared(s);
}
#[test]
fn sha1_hardware_bytes_bits_truncation_and_verification() -> Result<(), Error> {
    let _guard = RESOURCES.lock().map_err(|_| Error::Invariant)?;
    for width in [10, 20] {
        let mut owner = session(width)?;
        assert_eq!(owner.tag_bytes(), width);
        assert_eq!(
            Some(owner.backend()),
            brynja_legacy_hmac::execution::Sha1Executor::for_compiled_target(
                brynja_legacy_hmac::execution::Sha1Mode::Require
            )
            .map_err(|_| Error::Invariant)?
            .report()
            .backend
        );
        for key_len in [0, 1, 63, 64, 65, 257] {
            let key = vec![0x5a; key_len];
            for len in [0, 1, 55, 56, 63, 64, 65, 4097] {
                for valid_bits in 1..=8 {
                    let mut message = vec![0x31; len];
                    if let Some(last) = message.last_mut() {
                        *last = 0x80;
                    }
                    let tail = Bits {
                        bytes: &message,
                        valid_bits: if len == 0 { 0 } else { valid_bits },
                    };
                    let request = || Request {
                        key: &key,
                        chunks: &[b"pre", b"", b"fix"],
                        tail,
                    };
                    let mut reference =
                        Hmac::<Sha1>::with_tag_length(LegacyUse::acknowledge(), &key, width)
                            .map_err(Error::Mac)?;
                    reference.update(b"prefix").map_err(Error::Mac)?;
                    let mut expected = vec![0; width];
                    let _ = reference
                        .finalize_bits_tag(
                            BitString::new(tail.bytes, tail.valid_bits)
                                .map_err(|_| Error::InvalidBits)?,
                            &mut expected,
                        )
                        .map_err(Error::Mac)?;
                    assert_eq!(
                        owner.compute(request(), &Cancellation::new())?.expose(),
                        expected
                    );
                    assert_eq!(
                        owner.verify(request(), &expected, &Cancellation::new()),
                        Ok(())
                    );
                    for index in 0..width {
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
    }
    Ok(())
}
#[test]
fn every_hardware_boundary_clears_and_classifies_failure() -> Result<(), Error> {
    let _guard = RESOURCES.lock().map_err(|_| Error::Invariant)?;
    for verifying in [false, true] {
        let candidate = [0; 20];
        let points = if verifying { 6 } else { 7 };
        let invoke = |s: &mut Sha1CompiledSession, c: &Cancellation| {
            s.execute(
                request(),
                if verifying { Some(&candidate) } else { None },
                c,
            )
        };
        for point in 0..points {
            let mut s = session(20)?;
            core::mem::forget(s.authenticate(b"old key", b"old message")?);
            s.inner.fault = WorkerFault::Cancel(point);
            assert_eq!(invoke(&mut s, &Cancellation::new()), Err(Error::Cancelled));
            cleared(&s);
            reusable(&mut s)?;
            s.inner.fault = WorkerFault::Panic(point);
            assert_eq!(
                invoke(&mut s, &Cancellation::new()),
                Err(Error::Resource(macos_resident::Error::WorkerPanicked))
            );
            terminal(&mut s);
            drop(s);
            let mut s = session(20)?;
            s.fault = Fault::Revoke(point);
            s.inner.fault = WorkerFault::Cancel(point); // Integrity error wins.
            assert_eq!(
                invoke(&mut s, &Cancellation::new()),
                Err(Error::Mac(brynja_legacy_hmac::Error::ExecutionFailed))
            );
            terminal(&mut s);
        }
        let mut s = session(20)?;
        s.fault = Fault::WrongShape;
        assert_eq!(invoke(&mut s, &Cancellation::new()), Err(Error::Invariant));
        terminal(&mut s);
    }
    for panic in [false, true] {
        let mut s = session(20)?;
        s.inner.fault = if panic {
            WorkerFault::AfterWritePanic
        } else {
            WorkerFault::AfterWriteCancel
        };
        assert!(s.authenticate(b"key", b"message").is_err());
        cleared(&s);
        if panic {
            terminal(&mut s);
        } else {
            reusable(&mut s)?;
        }
    }
    let mut s = session(20)?;
    s.backend = if s.backend == Sha1Backend::X86Sha {
        Sha1Backend::Aarch64Sha1
    } else {
        Sha1Backend::X86Sha
    };
    assert!(matches!(
        s.authenticate(b"key", b"message"),
        Err(Error::Invariant)
    ));
    terminal(&mut s);
    Ok(())
}
#[test]
fn hardware_request_rejection_output_loans_and_explicit_quarantine() -> Result<(), Error> {
    let _guard = RESOURCES.lock().map_err(|_| Error::Invariant)?;
    let mut s = session(20)?;
    // Invalid metadata must erase forgotten output and stale staging without
    // running a worker, and must not permanently disable a healthy session.
    core::mem::forget(s.authenticate(b"key", b"message")?);
    s.inner.staging.as_bytes_mut().fill(0x5a);
    assert_eq!(
        s.verify(request(), &[0; 19], &Cancellation::new()),
        Err(crate::VerificationError::Operation(Error::OutputLength))
    );
    cleared(&s);
    reusable(&mut s)?;
    let mut limited = request();
    let large_key = [0; 8193];
    limited.key = &large_key;
    assert!(matches!(
        s.compute(limited, &Cancellation::new()),
        Err(Error::WorkLimit)
    ));
    reusable(&mut s)?;
    let mut bad = request();
    bad.tail = Bits {
        bytes: &[255],
        valid_bits: 3,
    };
    assert!(matches!(
        s.compute(bad, &Cancellation::new()),
        Err(Error::InvalidBits)
    ));
    cleared(&s);
    reusable(&mut s)?;
    let cancel = Cancellation::new();
    cancel.cancel();
    assert!(matches!(
        s.compute(request(), &cancel),
        Err(Error::Cancelled)
    ));
    reusable(&mut s)?;
    let mut public = [0x5a; 19];
    assert_eq!(
        s.authenticate(b"key", b"message")?.declassify(
            &mut public,
            super::super::super::PublicDeclassification::acknowledge()
        ),
        Err(Error::OutputLength)
    );
    assert_eq!(public, [0x5a; 19]);
    cleared(&s);
    core::mem::forget(s.authenticate(b"key", b"message")?);
    s.inner.staging.as_bytes_mut().fill(0xa7);
    s.quarantine();
    terminal(&mut s);
    Ok(())
}
