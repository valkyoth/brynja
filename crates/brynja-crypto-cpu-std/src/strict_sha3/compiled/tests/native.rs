use super::*;
fn kernels() -> impl Iterator<Item = Kernel> {
    // Independently pin compiled eligibility: a broken admission check must not
    // turn an accelerated build into a vacuous successful differential loop.
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
fn cleared(session: &CompiledSession) {
    assert!(session.inner.output.as_bytes().iter().all(|b| *b == 0));
}
fn compare(
    algorithm: Algorithm,
    kernel: Kernel,
    len: usize,
    valid: u8,
    customized: bool,
) -> Result<(), Error> {
    let mut cpu = CompiledSession::new(algorithm, kernel, limits())?;
    let mut scalar = Session::new(algorithm, limits())?;
    let mut input: Vec<u8> = (0..=250).cycle().take(len).collect();
    if let Some(last) = input.last_mut() {
        *last &= u8::MAX >> 8_u8.checked_sub(valid).ok_or(Error::Invariant)?;
    }
    let valid = if input.is_empty() { 0 } else { valid };
    let split = len.saturating_sub(1).min(17);
    let (head, tail) = input.split_at(split);
    let make_tail = || Bits {
        bytes: tail,
        valid_bits: valid,
    };
    let make_name = || {
        if customized {
            Bits {
                bytes: &[5],
                valid_bits: 3,
            }
        } else {
            Bits::empty()
        }
    };
    let make_custom = || {
        if customized {
            Bits {
                bytes: &[0xab, 1],
                valid_bits: 1,
            }
        } else {
            Bits::empty()
        }
    };
    let chunks: &[&[u8]] = &[&[], head, &[]];
    let expected = scalar.hash_customized_chunks(
        chunks,
        make_tail(),
        make_name(),
        make_custom(),
        &Cancellation::new(),
    )?;
    let output = cpu.hash_customized_chunks(
        chunks,
        make_tail(),
        make_name(),
        make_custom(),
        &Cancellation::new(),
    )?;
    assert_eq!(output.algorithm(), algorithm);
    assert_eq!(output.expose(), expected.expose());
    drop(output);
    cleared(&cpu);
    assert!(!cpu.is_quarantined());
    assert_eq!(cpu.kernel(), kernel);
    assert_eq!(cpu.algorithm(), algorithm);
    Ok(())
}
#[test]
fn native_all_identities_bits_prefixes_rates_and_multichunk_output() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    for kernel in kernels() {
        let mut cases = 0usize;
        for algorithm in [
            Algorithm::Sha3_224,
            Algorithm::Sha3_256,
            Algorithm::Sha3_384,
            Algorithm::Sha3_512,
        ] {
            for len in [0, 1, 71, 72, 103, 104, 135, 136, 143, 144, 167, 168, 4097] {
                for valid in 1..=8 {
                    compare(algorithm, kernel, len, valid, false)?;
                    cases = cases.checked_add(1).ok_or(Error::Invariant)?;
                }
            }
        }
        for bits in [0, 1, 7, 8, 9, 1088, 1344, 32768, 32777] {
            for algorithm in [
                Algorithm::Shake128(bits),
                Algorithm::Shake256(bits),
                Algorithm::Cshake128(bits),
                Algorithm::Cshake256(bits),
            ] {
                for valid in 1..=8 {
                    compare(algorithm, kernel, 4097, valid, false)?;
                    cases = cases.checked_add(1).ok_or(Error::Invariant)?;
                    if algorithm.customized() {
                        compare(algorithm, kernel, 169, valid, true)?;
                        cases = cases.checked_add(1).ok_or(Error::Invariant)?;
                    }
                }
            }
        }
        assert_eq!(cases, 848);
        println!("STRICT_SHA3_COMPILED: {kernel:?}; differential_cases={cases}");
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
    let name = if algorithm.customized() {
        Bits::bytes(b"secret function name")
    } else {
        Bits::empty()
    };
    let customization = if algorithm.customized() {
        Bits::bytes(b"secret customization")
    } else {
        Bits::empty()
    };
    let input = [0xa5; 4097];
    let result = cpu.hash_customized_chunks(
        &[&input],
        Bits::empty(),
        name,
        customization,
        &Cancellation::new(),
    );
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
    drop(result);
    cleared(&cpu);
    assert_eq!(cpu.is_quarantined(), !cancelled);
    cpu.fault = Fault::None;
    if cancelled {
        drop(cpu.hash(b"reusable")?);
    } else {
        assert!(matches!(
            cpu.hash(b"must not recreate authority"),
            Err(Error::Quarantined)
        ));
    }
    cleared(&cpu);
    Ok(())
}
#[test]
fn cancellation_reuses_but_revocation_and_unwind_never_revive() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    for kernel in kernels() {
        for algorithm in [
            Algorithm::Sha3_224,
            Algorithm::Sha3_256,
            Algorithm::Sha3_384,
            Algorithm::Sha3_512,
            Algorithm::Shake128(65543),
            Algorithm::Shake256(65543),
            Algorithm::Cshake128(65543),
            Algorithm::Cshake256(65543),
        ] {
            for point in [
                Boundary::Prefix,
                Boundary::Update,
                Boundary::Finalize,
                Boundary::Output,
            ] {
                fault_case(kernel, algorithm, Fault::Cancel(point), true)?;
                fault_case(kernel, algorithm, Fault::Revoke(point), false)?;
                fault_case(kernel, algorithm, Fault::Panic(point), false)?;
            }
            if algorithm.output_bits() > 512 {
                fault_case(kernel, algorithm, Fault::CancelSecondOutput, true)?;
                fault_case(kernel, algorithm, Fault::RevokeSecondOutput, false)?;
                fault_case(kernel, algorithm, Fault::PanicSecondOutput, false)?;
            }
        }
    }
    Ok(())
}
#[test]
fn preflight_canonicality_empty_output_and_forgotten_loans() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    for kernel in kernels() {
        let mut cpu = CompiledSession::new(
            Algorithm::Cshake128(9),
            kernel,
            Limits {
                max_message_bits: 64,
                ..limits()
            },
        )?;
        core::mem::forget(cpu.hash(b"secret")?);
        assert!(matches!(
            cpu.hash(b"over the message budget"),
            Err(Error::WorkLimit)
        ));
        cleared(&cpu);
        for slot in 0..3 {
            let bits = |selected| {
                if slot == selected {
                    Bits {
                        bytes: &[0xff],
                        valid_bits: 1,
                    }
                } else {
                    Bits::empty()
                }
            };
            assert!(matches!(
                cpu.hash_customized_chunks(&[], bits(0), bits(1), bits(2), &Cancellation::new()),
                Err(Error::InvalidBits)
            ));
            cleared(&cpu);
            assert!(!cpu.is_quarantined());
        }
        let cancel = Cancellation::new();
        cancel.cancel();
        assert!(matches!(
            cpu.hash_chunks(&[], Bits::empty(), &cancel),
            Err(Error::Cancelled)
        ));
        assert!(!cpu.is_quarantined());
        core::mem::forget(cpu.hash(b"secret")?);
        cpu.quarantine();
        cleared(&cpu);
        assert!(matches!(cpu.hash(b""), Err(Error::Quarantined)));
        for algorithm in [Algorithm::Shake128(0), Algorithm::Cshake256(0)] {
            let mut empty = CompiledSession::new(algorithm, kernel, limits())?;
            assert!(
                empty
                    .hash(b"empty output still finalizes")?
                    .expose()
                    .is_empty()
            );
            empty.fault = Fault::Revoke(Boundary::Output);
            assert!(matches!(empty.hash(b""), Err(Error::Backend(_))));
            assert!(empty.is_quarantined());
            cleared(&empty);
        }
        let mut fixed = CompiledSession::new(Algorithm::Sha3_256, kernel, limits())?;
        assert!(matches!(
            fixed.hash_customized_chunks(
                &[],
                Bits::empty(),
                Bits::bytes(b"N"),
                Bits::empty(),
                &Cancellation::new()
            ),
            Err(Error::Customization)
        ));
        assert!(!fixed.is_quarantined());
        drop(fixed.hash(b"reusable")?);
    }
    Ok(())
}
