use super::*;
fn kernels() -> impl Iterator<Item = Kernel> {
    assert_eq!(
        Kernel::X86Keccak.check_compiled_target().is_ok(),
        cfg!(all(
            target_arch = "x86_64",
            target_feature = "avx",
            target_feature = "avx2"
        ))
    );
    assert_eq!(
        Kernel::ArmKeccak.check_compiled_target().is_ok(),
        cfg!(all(
            target_arch = "aarch64",
            target_feature = "neon",
            target_feature = "sha3"
        ))
    );
    [Kernel::X86Keccak, Kernel::ArmKeccak]
        .into_iter()
        .filter(|k| k.check_compiled_target().is_ok())
}
fn algorithms(bits: usize) -> [Algorithm; 4] {
    [
        Algorithm::Kmac128(bits),
        Algorithm::Kmac256(bits),
        Algorithm::KmacXof128(bits),
        Algorithm::KmacXof256(bits),
    ]
}
fn cleared(session: &CompiledSession) {
    assert!(
        session
            .inner
            .output
            .as_bytes()
            .iter()
            .chain(session.inner.staging.as_bytes())
            .all(|b| *b == 0)
    );
}
fn request<'a>(key: &'a [u8], chunks: &'a [&'a [u8]]) -> Request<'a> {
    Request {
        key: Bits::bytes(key),
        customization: Bits::bytes(b"private domain"),
        chunks,
        tail: Bits::empty(),
    }
}
fn valid(bits: usize) -> Result<u8, Error> {
    if bits == 0 {
        return Ok(0);
    }
    u8::try_from(
        (bits.checked_sub(1).ok_or(Error::Invariant)? % 8)
            .checked_add(1)
            .ok_or(Error::Invariant)?,
    )
    .map_err(|_| Error::Invariant)
}
#[test]
fn native_all_identities_partial_keys_messages_outputs_and_long_xof() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    for kernel in kernels() {
        let mut cases = 0usize;
        for bits in [256, 257, 32777] {
            for algorithm in algorithms(bits) {
                let mut cpu = CompiledSession::new(algorithm, kernel, limits())?;
                let mut scalar = Session::new(algorithm, limits())?;
                for len in [0, 135, 136, 167, 168, 4097] {
                    for last_bits in 1..=8 {
                        let mask =
                            u8::MAX >> 8_u8.checked_sub(last_bits).ok_or(Error::Invariant)?;
                        let mut key = [0xa5; 33];
                        key[32] &= mask;
                        let mut input: Vec<u8> = (0..=250).cycle().take(len).collect();
                        if let Some(last) = input.last_mut() {
                            *last &= mask;
                        }
                        let split = len.saturating_sub(1).min(17);
                        let (head, tail) = input.split_at(split);
                        let chunks: &[&[u8]] = &[&[], head, &[]];
                        let make = || Request {
                            key: Bits {
                                bytes: &key,
                                valid_bits: last_bits,
                            },
                            customization: Bits {
                                bytes: &[0xab, 1],
                                valid_bits: 1,
                            },
                            chunks,
                            tail: Bits {
                                bytes: tail,
                                valid_bits: if tail.is_empty() { 0 } else { last_bits },
                            },
                        };
                        let expected = scalar.compute(make(), &Cancellation::new())?;
                        let output = cpu.compute(make(), &Cancellation::new())?;
                        assert_eq!(output.algorithm(), algorithm);
                        assert_eq!(output.expose(), expected.expose());
                        drop(output);
                        drop(expected);
                        cleared(&cpu);
                        assert!(!cpu.is_quarantined());
                        assert_eq!(cpu.kernel(), kernel);
                        assert_eq!(cpu.algorithm(), algorithm);
                        cases = cases.checked_add(1).ok_or(Error::Invariant)?;
                    }
                }
            }
        }
        assert_eq!(cases, 576);
        println!("STRICT_KMAC_COMPILED: {kernel:?}; differential_cases={cases}");
    }
    Ok(())
}
fn tag(bytes: &[u8], valid_bits: u8) -> Bits<'_> {
    Bits { bytes, valid_bits }
}
#[test]
fn verification_full_width_first_middle_last_mismatches_and_cleanup() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    for kernel in kernels() {
        for bits in [256, 257, 65543] {
            for algorithm in algorithms(bits) {
                let mut cpu = CompiledSession::new(algorithm, kernel, limits())?;
                let mut scalar = Session::new(algorithm, limits())?;
                let key = [0x42; 32];
                let chunks: &[&[u8]] = &[b"message", b"boundary"];
                let expected = scalar
                    .compute(request(&key, chunks), &Cancellation::new())?
                    .expose()
                    .to_vec();
                assert!(cpu.verify(
                    request(&key, chunks),
                    tag(&expected, valid(bits)?),
                    &Cancellation::new()
                )?);
                cleared(&cpu);
                for index in [
                    0,
                    expected.len() / 2,
                    expected.len().checked_sub(1).ok_or(Error::Invariant)?,
                ] {
                    let mut wrong = expected.clone();
                    *wrong.get_mut(index).ok_or(Error::Invariant)? ^= 1;
                    assert!(!cpu.verify(
                        request(&key, chunks),
                        tag(&wrong, valid(bits)?),
                        &Cancellation::new()
                    )?);
                    cleared(&cpu);
                    assert!(!cpu.is_quarantined());
                }
                assert!(cpu.verify(
                    request(&key, chunks),
                    tag(&expected, valid(bits)?),
                    &Cancellation::new()
                )?);
                cleared(&cpu);
                if bits > 32768 {
                    cpu.fault = Fault::CancelDuringComparison;
                    assert!(matches!(
                        cpu.verify(
                            request(&key, chunks),
                            tag(&expected, valid(bits)?),
                            &Cancellation::new()
                        ),
                        Err(Error::Cancelled)
                    ));
                    cleared(&cpu);
                    assert!(!cpu.is_quarantined());
                    cpu.fault = Fault::None;
                    assert!(cpu.verify(
                        request(&key, chunks),
                        tag(&expected, valid(bits)?),
                        &Cancellation::new()
                    )?);
                }
            }
        }
    }
    Ok(())
}
fn fault_case(
    kernel: Kernel,
    algorithm: Algorithm,
    fault: Fault,
    cancelled: bool,
) -> Result<(), Error> {
    let mut cpu = CompiledSession::new(algorithm, kernel, limits())?;
    cpu.fault = fault;
    let key = [0x42; 32];
    let input = [0xa5; 4097];
    let chunks: &[&[u8]] = &[&input];
    let verifying = matches!(
        fault,
        Fault::Cancel(Boundary::Compare | Boundary::Compared)
            | Fault::Revoke(Boundary::Compare | Boundary::Compared)
            | Fault::Panic(Boundary::Compare | Boundary::Compared)
    );
    let result = if verifying {
        let candidate = vec![0; algorithm.output_bytes()];
        cpu.verify(
            request(&key, chunks),
            Bits {
                bytes: &candidate,
                valid_bits: valid(algorithm.output_bits())?,
            },
            &Cancellation::new(),
        )
        .map(|_| ())
    } else {
        cpu.compute(request(&key, chunks), &Cancellation::new())
            .map(drop)
    };
    if cancelled {
        assert!(matches!(result, Err(Error::Cancelled)));
    } else if matches!(fault, Fault::Revoke(_) | Fault::RevokeSecondOutput) {
        assert!(matches!(
            result,
            Err(Error::Backend(
                brynja_crypto_cpu::static_execution::Error::Quarantined
            ))
        ));
    } else {
        assert!(matches!(
            result,
            Err(Error::Resource(
                crate::protected_memory::Error::WorkerPanicked
            ))
        ));
    }
    cleared(&cpu);
    assert_eq!(cpu.is_quarantined(), !cancelled);
    cpu.fault = Fault::None;
    if cancelled {
        drop(cpu.authenticate(&key, b"reusable", b"")?);
    } else {
        assert!(matches!(
            cpu.authenticate(&key, b"no revival", b""),
            Err(Error::Quarantined)
        ));
    }
    cleared(&cpu);
    Ok(())
}
#[test]
fn cancellation_reuse_and_terminal_backend_unwind_at_all_boundaries() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    for kernel in kernels() {
        for algorithm in algorithms(65543) {
            for point in [
                Boundary::Setup,
                Boundary::Update,
                Boundary::Finalize,
                Boundary::Output,
                Boundary::Compare,
                Boundary::Compared,
            ] {
                fault_case(kernel, algorithm, Fault::Cancel(point), true)?;
                fault_case(kernel, algorithm, Fault::Revoke(point), false)?;
                fault_case(kernel, algorithm, Fault::Panic(point), false)?;
            }
            if algorithm.xof() {
                fault_case(kernel, algorithm, Fault::CancelSecondOutput, true)?;
                fault_case(kernel, algorithm, Fault::RevokeSecondOutput, false)?;
                fault_case(kernel, algorithm, Fault::PanicSecondOutput, false)?;
            }
        }
    }
    Ok(())
}

#[test]
fn strength_canonicality_bounds_empty_output_and_forgotten_loans() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    for kernel in kernels() {
        for weak in [Algorithm::Kmac128(127), Algorithm::Kmac256(255)] {
            assert!(matches!(
                CompiledSession::new(weak, kernel, limits()),
                Err(Error::TagTooShort)
            ));
        }
        for algorithm in algorithms(257) {
            let mut cpu = CompiledSession::new(
                algorithm,
                kernel,
                Limits {
                    max_message_bits: 64,
                    ..limits()
                },
            )?;
            let key = vec![0x42; algorithm.strength() / 8];
            core::mem::forget(cpu.authenticate(&key, b"secret", b"")?);
            assert!(matches!(
                cpu.authenticate(&key, b"over the budget", b""),
                Err(Error::WorkLimit)
            ));
            cleared(&cpu);
            assert!(!cpu.is_quarantined());
            let short = key
                .get(..key.len().checked_sub(1).ok_or(Error::Invariant)?)
                .ok_or(Error::Invariant)?;
            assert!(matches!(
                cpu.authenticate(short, b"", b""),
                Err(Error::KeyTooShort)
            ));
            cleared(&cpu);
            for slot in 0..3 {
                let make = || Request {
                    key: if slot == 0 {
                        Bits {
                            bytes: &[0xff; 33],
                            valid_bits: 1,
                        }
                    } else {
                        Bits::bytes(&key)
                    },
                    customization: if slot == 1 {
                        Bits {
                            bytes: &[0xff],
                            valid_bits: 1,
                        }
                    } else {
                        Bits::empty()
                    },
                    chunks: &[],
                    tail: if slot == 2 {
                        Bits {
                            bytes: &[0xff],
                            valid_bits: 1,
                        }
                    } else {
                        Bits::empty()
                    },
                };
                assert!(matches!(
                    cpu.compute(make(), &Cancellation::new()),
                    Err(Error::InvalidBits)
                ));
                assert!(!cpu.is_quarantined());
                cleared(&cpu);
            }
            assert!(matches!(
                cpu.verify(
                    request(&key, &[]),
                    tag(&[0xff; 33], 1),
                    &Cancellation::new()
                ),
                Err(Error::InvalidBits)
            ));
            cleared(&cpu);
            assert!(matches!(
                cpu.verify(
                    request(&key, &[]),
                    Bits::bytes(&[0; 32]),
                    &Cancellation::new()
                ),
                Err(Error::OutputLength)
            ));
            let cancel = Cancellation::new();
            cancel.cancel();
            assert!(matches!(
                cpu.compute(request(&key, &[]), &cancel),
                Err(Error::Cancelled)
            ));
            assert!(!cpu.is_quarantined());
            cleared(&cpu);
            drop(cpu.authenticate(&key, b"reusable", b"")?);
            core::mem::forget(cpu.authenticate(&key, b"secret", b"")?);
            cpu.quarantine();
            cleared(&cpu);
            assert!(matches!(
                cpu.authenticate(&key, b"", b""),
                Err(Error::Quarantined)
            ));
            assert!(matches!(
                cpu.verify(request(&key, &[]), tag(&[0; 33], 1), &Cancellation::new()),
                Err(Error::Quarantined)
            ));
        }
        for bits in [0, 1, 7, 8, 9] {
            for algorithm in [Algorithm::KmacXof128(bits), Algorithm::KmacXof256(bits)] {
                let mut cpu = CompiledSession::new(algorithm, kernel, limits())?;
                let mut scalar = Session::new(algorithm, limits())?;
                let output = cpu.authenticate(&[0x42; 32], b"short derived output", b"")?;
                assert_eq!(
                    output.expose(),
                    scalar
                        .authenticate(&[0x42; 32], b"short derived output", b"")?
                        .expose()
                );
                drop(output);
                cleared(&cpu);
                let candidate = vec![0; algorithm.output_bytes()];
                assert!(matches!(
                    cpu.verify(
                        request(&[0x42; 32], &[]),
                        tag(&candidate, valid(bits)?),
                        &Cancellation::new()
                    ),
                    Err(Error::TagTooShort)
                ));
                assert!(!cpu.is_quarantined());
                cpu.fault = Fault::Revoke(Boundary::Output);
                assert!(matches!(
                    cpu.authenticate(&[0x42; 32], b"", b""),
                    Err(Error::Backend(_))
                ));
                assert!(cpu.is_quarantined());
                cleared(&cpu);
            }
        }
    }
    Ok(())
}
