use super::*;

#[test]
fn preadmission_and_every_boundary_release_owners() {
    let mut faults = 0;
    for kernel in Kernel::ALL {
        for key in [&[][..], &[0x5a; 64][..], &[0x5a; 65][..]] {
            for mode in MODES {
                let operate = |out: &mut [u8]| {
                    let mut mac = Hmac::<Synthetic>::create(Source::Synthetic(&kernel), key, 32)?;
                    assert_eq!(mac.kernel(), kernel);
                    mac.update(b"message")?;
                    finalize(mac, mode, out)
                };
                reset(key, kernel, 0, Fault::None);
                let mut output = [0x77; 32];
                let expected = if matches!(mode, Mode::Verify | Mode::BitVerify) {
                    Err(Error::Mismatch)
                } else {
                    Ok(())
                };
                assert_eq!(operate(&mut output), expected);
                let events = closed();
                let admitted = if key.len() > 64 { 3 } else { 2 };
                assert!(
                    events[..admitted]
                        .iter()
                        .all(|event| *event == Event::Admit)
                );
                assert!(!events[admitted..].contains(&Event::Admit));
                // Constructor and streaming update finish before output admission.
                let final_at = events
                    .iter()
                    .enumerate()
                    .filter(|(_, event)| **event == Event::Update)
                    .nth(if key.len() > 64 { 3 } else { 2 })
                    .unwrap()
                    .0
                    + 1;
                for fail_at in 1..=events.len() {
                    for fault in [Fault::Error, Fault::Unwind] {
                        reset(key, kernel, fail_at, fault);
                        let mut output = [0x77; 32];
                        let result = catch_unwind(AssertUnwindSafe(|| operate(&mut output)));
                        match fault {
                            Fault::Error => {
                                assert!(matches!(result, Ok(Err(Error::ExecutionFailed))))
                            }
                            Fault::Unwind => assert!(result.is_err()),
                            Fault::None => unreachable!(),
                        }
                        assert_eq!(closed(), events[..fail_at]);
                        let cleared =
                            matches!(mode, Mode::Secret | Mode::BitSecret) && fail_at > final_at;
                        assert_eq!(output, [if cleared { 0 } else { 0x77 }; 32]);
                        faults += 1;
                    }
                }
            }
        }
    }
    // Exact population guards against accidentally dropping a route/mode/path.
    assert_eq!(faults, 2784);
}

#[test]
fn terminal_state_rejects_every_operation() {
    let kernel = Kernel::X86Sha256;
    for mode in MODES {
        for fault in [Fault::Error, Fault::Unwind] {
            reset(b"key", kernel, 0, Fault::None);
            let mut mac =
                Hmac::<Synthetic>::create(Source::Synthetic(&kernel), b"key", 32).unwrap();
            TRACE.with(|trace| {
                let mut trace = trace.borrow_mut();
                trace.fail_at = trace.events.len() + 1;
                trace.fault = fault;
            });
            let failed = catch_unwind(AssertUnwindSafe(|| mac.update(b"message")));
            match fault {
                Fault::Error => assert_eq!(failed.unwrap(), Err(Error::ExecutionFailed)),
                Fault::Unwind => assert!(failed.is_err()),
                _ => unreachable!(),
            }
            let steps = closed();
            assert_eq!(mac.update(&[]), Err(Error::ExecutionFailed));
            assert_eq!(mac.update(b"no resurrection"), Err(Error::ExecutionFailed));
            let mut output = [0x77; 32];
            let result = finalize(mac, mode, &mut output);
            if matches!(mode, Mode::Cancel) {
                assert!(result.is_ok());
            } else {
                assert_eq!(result, Err(Error::ExecutionFailed));
            }
            assert_eq!(closed(), steps, "terminal operation entered a backend");
            assert_eq!(
                output,
                [if matches!(mode, Mode::Secret | Mode::BitSecret) {
                    0
                } else {
                    0x77
                }; 32]
            );
        }
    }
}

#[test]
fn length_rejection_preserves_both_owners() {
    let kernel = Kernel::ArmSha256;
    reset(b"key", kernel, 0, Fault::None);
    let mut mac = Hmac::<Synthetic>::create(Source::Synthetic(&kernel), b"key", 32).unwrap();
    assert_eq!(
        mac.update(b"atomic length rejection"),
        Err(Error::MessageTooLong)
    );
    TRACE.with(|trace| {
        assert_eq!(trace.borrow().live, 2);
        assert_eq!(trace.borrow().dropped, 0);
    });
    assert!(mac.update(b"after rejection").is_ok());
    assert!(mac.finalize_tag(&mut [0; 32]).is_ok());
    closed();
}

#[test]
fn invalid_policy_admits_nothing() {
    let kernel = Kernel::ArmSha256;
    for tag in [0, 1, 15, 33, usize::MAX] {
        reset(b"key", kernel, 0, Fault::None);
        assert!(matches!(
            Hmac::<Synthetic>::create(Source::Synthetic(&kernel), b"key", tag),
            Err(Error::TagLength)
        ));
        assert!(closed().is_empty());
    }
    reset(b"key", kernel, 0, Fault::None);
    TRACE.with(|trace| trace.borrow_mut().invalid = true);
    assert!(matches!(
        Hmac::<Synthetic>::create(Source::Synthetic(&kernel), b"key", 32),
        Err(Error::AlgorithmParameter)
    ));
    assert!(closed().is_empty());
}

#[test]
fn invalid_outputs_release_owners_without_finalization() {
    let kernel = Kernel::ArmSha256;
    for tag in [16, 32] {
        for length in [0, 1, 15, 17, 31, 33] {
            for mode in MODES
                .into_iter()
                .filter(|mode| !matches!(mode, Mode::Cancel))
            {
                reset(b"key", kernel, 0, Fault::None);
                let mac =
                    Hmac::<Synthetic>::create(Source::Synthetic(&kernel), b"key", tag).unwrap();
                let steps = TRACE.with(|trace| trace.borrow().events.clone());
                let mut output = std::vec![0x77; length];
                assert_eq!(finalize(mac, mode, &mut output), Err(Error::TagLength));
                assert_eq!(closed(), steps);
                assert!(output.iter().all(|byte| *byte
                    == if matches!(mode, Mode::Secret | Mode::BitSecret) {
                        0
                    } else {
                        0x77
                    }));
            }
        }
    }
}

#[test]
fn missing_factory_cannot_construct_an_adapter() {
    use sealed::Hash;
    assert!(matches!(
        Adapter::<Synthetic>::start(),
        Err(Error::ExecutionFailed)
    ));
}
