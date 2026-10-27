use facade::hmac::*;

fn limits() -> Limits {
    Limits {
        stack_bytes: 262144,
        max_stack_mapping_bytes: 1048576,
        max_buffer_mapping_bytes: 65536,
        max_key_bytes: 4096,
        max_message_bits: 65536,
        max_chunks: 16,
    }
}

#[test]
fn explicit_route_admission_and_no_fallback() -> Result<(), Error> {
    let family = std::env::var("BRYNJA_STRICT_HMAC_ROUTE").map_err(|_| Error::Invariant)?;
    let expected = std::env::var("BRYNJA_STRICT_HMAC_EXPECT").map_err(|_| Error::Invariant)?;
    assert!(matches!(
        expected.as_str(),
        "native" | "missing-features" | "unsupported-platform"
    ));
    let arm = cfg!(target_arch = "aarch64");
    let mut checked = 0;
    macro_rules! check {
        ($identity:ty, $kernel:expr, $bytes:literal) => {{
            let kernel = $kernel;
            assert_eq!(
                kernel.check_compiled_target().is_ok(),
                expected != "missing-features"
            );
            let constructed = CompiledSession::<$identity>::new(TagPolicy::Full, kernel, limits());
            match expected.as_str() {
                "missing-features" => assert!(matches!(constructed, Err(Error::Backend(_)))),
                "unsupported-platform" => assert!(matches!(constructed, Err(Error::Resource(_)))),
                "native" => {
                    let mut session = constructed?;
                    assert_eq!(session.kernel(), kernel);
                    let key = [0x51; 257];
                    let request = || Request {
                        key: &key,
                        chunks: &[b"packaged"],
                        tail: Bits::empty(),
                    };
                    let mut scalar = Session::<$identity>::new(TagPolicy::Full, limits())?;
                    let mut reference = [0; $bytes];
                    scalar
                        .compute(request(), &Cancellation::new())?
                        .declassify(&mut reference, PublicDeclassification::acknowledge())?;
                    for _ in 0..2 {
                        let output = session.compute(request(), &Cancellation::new())?;
                        assert_eq!(output.expose(), reference);
                        drop(output);
                        assert_eq!(session.verify(request(), &reference, &Cancellation::new()), Ok(()));
                        let mut wrong = reference;
                        wrong[0] ^= 1;
                        assert_eq!(session.verify(request(), &wrong, &Cancellation::new()), Err(Error::Mismatch));
                    }
                    let cancel = Cancellation::new();
                    cancel.cancel();
                    assert!(matches!(
                        session.compute(request(), &cancel),
                        Err(Error::Cancelled)
                    ));
                    assert!(!session.is_quarantined());
                    drop(session.authenticate(&key, b"packaged")?);
                    session.quarantine();
                    assert!(session.is_quarantined());
                    assert!(matches!(
                        session.authenticate(&key, b"packaged"),
                        Err(Error::Quarantined)
                    ));
                }
                _ => unreachable!(),
            }
            checked += 1;
        }};
    }
    match family.as_str() {
        "sha256" => {
            let kernel = if arm {
                Kernel::ArmSha256
            } else {
                Kernel::X86Sha256
            };
            check!(Sha224, kernel, 28);
            check!(Sha256, kernel, 32);
            assert_eq!(checked, 2);
        }
        "sha512" => {
            let kernel = if arm {
                Kernel::ArmSha512
            } else {
                Kernel::X86Sha512
            };
            check!(Sha384, kernel, 48);
            check!(Sha512, kernel, 64);
            check!(Sha512_224, kernel, 28);
            check!(Sha512_256, kernel, 32);
            check!(Sha512T<129>, kernel, 17);
            check!(Sha512T<511>, kernel, 64);
            assert_eq!(checked, 6);
        }
        "keccak" => {
            let kernel = if arm {
                Kernel::ArmKeccak
            } else {
                Kernel::X86Keccak
            };
            check!(Sha3_224, kernel, 28);
            check!(Sha3_256, kernel, 32);
            check!(Sha3_384, kernel, 48);
            check!(Sha3_512, kernel, 64);
            assert_eq!(checked, 4);
        }
        _ => return Err(Error::Invariant),
    }
    println!("HMAC_STRICT_COMPILED: {family}; {expected}; {checked} identities");
    Ok(())
}
