use super::*;
use crate::strict_hmac::tests::Fault;
use brynja_mac_hmac as mac;

fn cleared<A: Algorithm + for<'a> mac::execution::Algorithm<'a>>(s: &CompiledSession<A>) {
    assert!(s.inner.staging.as_bytes().iter().all(|b| *b == 0));
    assert!(s.inner.output.as_bytes().iter().all(|b| *b == 0));
}
fn compare<A: Algorithm + for<'a> mac::execution::Algorithm<'a>>(
    kernel: Kernel,
    last: u8,
) -> Result<(), Error> {
    for policy in [TagPolicy::Full, TagPolicy::Bytes(16)] {
        let mut session = CompiledSession::<A>::new(policy, kernel, limits())?;
        session.inner.fault = Fault::Observe;
        assert_eq!(session.kernel(), kernel);
        for key_len in [
            0,
            1,
            A::BLOCK_BYTES,
            A::BLOCK_BYTES.checked_add(1).ok_or(Error::Invariant)?,
            257,
        ] {
            let key = vec![0x5a; key_len];
            let message = vec![0x31; 8193];
            let mut expected = vec![0; session.tag_bits().div_ceil(8)];
            let mut reference = match policy {
                TagPolicy::Full => mac::Hmac::<A>::new(&key),
                TagPolicy::Bytes(n) => mac::Hmac::<A>::with_tag_length(&key, n),
            }
            .map_err(Error::Mac)?;
            reference.update(&message).map_err(Error::Mac)?;
            let bits = Bits {
                bytes: &[last],
                valid_bits: 3,
            };
            let _ = reference
                .finalize_bits_tag(A::tail(bits)?, &mut expected)
                .map_err(Error::Mac)?;
            let chunks = [message.as_slice()];
            let request = || Request {
                key: &key,
                chunks: &chunks,
                tail: bits,
            };
            let output = session.compute(request(), &Cancellation::new())?;
            assert_eq!(output.expose(), expected);
            drop(output);
            cleared(&session);
            assert!(session.verify(request(), &expected, &Cancellation::new())?);
            for index in [0, expected.len().checked_sub(1).ok_or(Error::Invariant)?] {
                let mut wrong = expected.clone();
                *wrong.get_mut(index).ok_or(Error::Invariant)? ^= 1;
                assert!(!session.verify(request(), &wrong, &Cancellation::new())?);
                cleared(&session);
                assert!(!session.is_quarantined());
            }
        }
    }
    Ok(())
}
fn failures<A: Algorithm + for<'a> mac::execution::Algorithm<'a>>(
    kernel: Kernel,
) -> Result<(), Error> {
    // Every worker checkpoint: both compute and worker-side verification.
    for verifying in [false, true] {
        let count = if verifying { 6 } else { 7 };
        for point in 0..count {
            for (fault, quarantined) in [
                (Fault::Cancel(point), false),
                (Fault::Panic(point), true),
                (Fault::Revoke(point), true),
            ] {
                let mut s = CompiledSession::<A>::new(TagPolicy::Full, kernel, limits())?;
                let expected = s.authenticate(b"key", b"message")?.expose().to_vec();
                s.inner.fault = fault;
                let request = Request {
                    key: b"key",
                    chunks: &[b"message"],
                    tail: Bits::empty(),
                };
                let result = if verifying {
                    s.verify(request, &expected, &Cancellation::new())
                        .map(|_| ())
                } else {
                    s.compute(request, &Cancellation::new()).map(drop)
                };
                assert!(result.is_err());
                assert_eq!(s.is_quarantined(), quarantined);
                cleared(&s);
                s.inner.fault = Fault::None;
                if quarantined {
                    assert!(matches!(
                        s.authenticate(b"key", b"message"),
                        Err(Error::Quarantined)
                    ));
                } else {
                    drop(s.authenticate(b"key", b"message")?);
                }
            }
        }
    }
    let mut s = CompiledSession::<A>::new(TagPolicy::Full, kernel, limits())?;
    s.inner.fault = Fault::AfterWrite;
    assert!(matches!(
        s.authenticate(b"key", b"message"),
        Err(Error::Resource(
            crate::protected_memory::Error::WorkerPanicked
        ))
    ));
    assert!(s.is_quarantined());
    cleared(&s);
    let mut s = CompiledSession::<A>::new(TagPolicy::Full, kernel, limits())?;
    s.inner.limits.max_message_bits = 0;
    assert!(matches!(
        s.authenticate(b"key", b"message"),
        Err(Error::WorkLimit)
    ));
    assert!(!s.is_quarantined());
    s.inner.limits = limits();
    let bad = Request {
        key: b"key",
        chunks: &[],
        tail: Bits {
            bytes: &[255],
            valid_bits: 3,
        },
    };
    assert!(matches!(
        s.compute(bad, &Cancellation::new()),
        Err(Error::InvalidBits)
    ));
    assert!(!s.is_quarantined());
    let output = s.authenticate(b"key", b"message")?;
    core::mem::forget(output);
    s.quarantine();
    cleared(&s);
    assert!(matches!(
        s.authenticate(b"key", b"message"),
        Err(Error::Quarantined)
    ));
    Ok(())
}
#[test]
#[ignore = "requires native GNU/Linux and compiled SHA-256 target features; run explicitly"]
fn sha256_route() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    let kernel = if cfg!(target_arch = "aarch64") {
        Kernel::ArmSha256
    } else {
        Kernel::X86Sha256
    };
    compare::<Sha224>(kernel, 0xa0)?;
    compare::<Sha256>(kernel, 0xa0)?;
    failures::<Sha256>(kernel)
}
#[test]
#[ignore = "requires native GNU/Linux dedicated SHA-512 hardware and target features; run explicitly"]
fn sha512_route() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    let kernel = if cfg!(target_arch = "aarch64") {
        Kernel::ArmSha512
    } else {
        Kernel::X86Sha512
    };
    compare::<Sha384>(kernel, 0xa0)?;
    compare::<Sha512>(kernel, 0xa0)?;
    compare::<Sha512_224>(kernel, 0xa0)?;
    compare::<Sha512_256>(kernel, 0xa0)?;
    compare::<Sha512T<129>>(kernel, 0xa0)?;
    compare::<Sha512T<511>>(kernel, 0xa0)?;
    failures::<Sha512T<129>>(kernel)
}
#[test]
#[ignore = "requires native GNU/Linux and compiled Keccak target features; run explicitly"]
fn keccak_route() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    let kernel = if cfg!(target_arch = "aarch64") {
        Kernel::ArmKeccak
    } else {
        Kernel::X86Keccak
    };
    compare::<Sha3_224>(kernel, 5)?;
    compare::<Sha3_256>(kernel, 5)?;
    compare::<Sha3_384>(kernel, 5)?;
    compare::<Sha3_512>(kernel, 5)?;
    failures::<Sha3_256>(kernel)
}
