use super::*;
use crate::strict_sha2::Sha512TBits;
fn kernels() -> impl Iterator<Item = Kernel> {
    [
        Kernel::X86Sha256,
        Kernel::X86Sha512,
        Kernel::ArmSha256,
        Kernel::ArmSha512,
    ]
    .into_iter()
    .filter(|kernel| kernel.check_compiled_target().is_ok())
}
fn algorithms(kernel: Kernel) -> Vec<Algorithm> {
    if matches!(kernel, Kernel::X86Sha256 | Kernel::ArmSha256) {
        vec![Algorithm::Sha224, Algorithm::Sha256]
    } else {
        vec![
            Algorithm::Sha384,
            Algorithm::Sha512,
            Algorithm::Sha512_224,
            Algorithm::Sha512_256,
        ]
    }
}
fn cleared(session: &CompiledSession) {
    assert!(session.inner.output.as_bytes().iter().all(|b| *b == 0));
}
#[test]
fn required_kernels_match_scalar_bits_chunks_padding_and_real_blocks() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    for kernel in kernels() {
        let mut cases = 0usize;
        for algorithm in algorithms(kernel) {
            let mut cpu = CompiledSession::new(algorithm, kernel, limits())?;
            let mut scalar = Session::new(algorithm, limits())?;
            assert_eq!(cpu.algorithm(), algorithm);
            assert_eq!(cpu.kernel(), kernel);
            for len in [
                0, 1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 4097, 32768,
            ] {
                for valid in 1..=8 {
                    let mut input: Vec<u8> = (0..=250).cycle().take(len).collect();
                    if let Some(last) = input.last_mut() {
                        *last &= u8::MAX << (8 - valid);
                    }
                    let valid = if input.is_empty() { 0 } else { valid };
                    let split = len.saturating_sub(1).min(17);
                    let (head, tail) = input.split_at(split);
                    let chunks: &[&[u8]] = &[&[], head, &[]];
                    let expected = scalar.hash_chunks(chunks, tail, valid, &Cancellation::new())?;
                    let output = cpu.hash_chunks(chunks, tail, valid, &Cancellation::new())?;
                    assert_eq!(output.algorithm(), algorithm);
                    assert_eq!(output.expose(), expected.expose());
                    drop(output);
                    drop(expected);
                    cleared(&cpu);
                    assert!(!cpu.is_quarantined());
                    cases = cases.checked_add(1).ok_or(Error::Invariant)?;
                }
            }
            drop(cpu.hash(&[0x5a; 32768])?);
            let expected = if matches!(kernel, Kernel::X86Sha256 | Kernel::ArmSha256) {
                512
            } else {
                256
            };
            assert_eq!(LAST_MESSAGE_BLOCKS.load(Ordering::Relaxed), expected);
        }
        println!(
            "STRICT_SHA2_COMPILED: {kernel:?}; differential_cases={cases}; actual_message_blocks_verified"
        );
    }
    Ok(())
}
#[test]
fn all_general_t_parameters_keep_exact_identity_on_wide_kernels() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    for kernel in kernels().filter(|k| matches!(k, Kernel::X86Sha512 | Kernel::ArmSha512)) {
        for bits in 1..512 {
            if bits == 384 {
                continue;
            }
            let t = Sha512TBits::new(bits).map_err(|_| Error::Invariant)?;
            let algorithm = Algorithm::Sha512T(t);
            let mut cpu = CompiledSession::new(algorithm, kernel, limits())?;
            let mut scalar = Session::new(algorithm, limits())?;
            let output = cpu.hash(b"parameter-specific initialization")?;
            assert_eq!(output.algorithm(), algorithm);
            assert_eq!(
                output.expose(),
                scalar.hash(b"parameter-specific initialization")?.expose()
            );
            drop(output);
            cleared(&cpu);
        }
    }
    Ok(())
}
#[test]
fn cancellation_preserves_health_but_revocation_and_unwind_are_terminal() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    for kernel in kernels() {
        let algorithm = algorithms(kernel)
            .first()
            .copied()
            .ok_or(Error::Invariant)?;
        for point in [Point::Update, Point::Finalize, Point::Output] {
            let mut cpu = CompiledSession::new(algorithm, kernel, limits())?;
            cpu.fault = Fault::Cancel(point);
            assert!(matches!(cpu.hash(&[0xa5; 129]), Err(Error::Cancelled)));
            cleared(&cpu);
            assert!(!cpu.is_quarantined());
            cpu.fault = Fault::None;
            drop(cpu.hash(b"reusable")?);
            cleared(&cpu);
            for fault in [Fault::Revoke(point), Fault::Panic(point)] {
                let mut cpu = CompiledSession::new(algorithm, kernel, limits())?;
                cpu.fault = fault;
                let result = cpu.hash(&[0xa5; 129]);
                match fault {
                    Fault::Revoke(_) => assert!(matches!(
                        result,
                        Err(Error::Backend(
                            brynja_crypto_cpu::static_execution::Error::Quarantined
                        ))
                    )),
                    Fault::Panic(_) => assert!(matches!(
                        result,
                        Err(Error::Resource(
                            crate::protected_memory::Error::WorkerPanicked
                        ))
                    )),
                    _ => return Err(Error::Invariant),
                }
                drop(result);
                cleared(&cpu);
                assert!(cpu.is_quarantined());
                cpu.fault = Fault::None;
                assert!(matches!(
                    cpu.hash(b"must not recreate authority"),
                    Err(Error::Quarantined)
                ));
                cleared(&cpu);
            }
        }
    }
    Ok(())
}
#[test]
fn request_rejection_forgotten_loan_and_explicit_quarantine() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    for kernel in kernels() {
        let algorithm = algorithms(kernel)
            .first()
            .copied()
            .ok_or(Error::Invariant)?;
        let mut cpu = CompiledSession::new(
            algorithm,
            kernel,
            Limits {
                max_message_bits: 64,
                ..limits()
            },
        )?;
        core::mem::forget(cpu.hash(b"secret")?);
        assert!(matches!(
            cpu.hash(b"oversized message"),
            Err(Error::WorkLimit)
        ));
        cleared(&cpu);
        assert!(!cpu.is_quarantined());
        assert!(matches!(
            cpu.hash_chunks(&[], &[0xff], 1, &Cancellation::new()),
            Err(Error::InvalidBits)
        ));
        cleared(&cpu);
        assert!(!cpu.is_quarantined());
        let cancel = Cancellation::new();
        cancel.cancel();
        assert!(matches!(
            cpu.hash_chunks(&[], &[], 0, &cancel),
            Err(Error::Cancelled)
        ));
        assert!(!cpu.is_quarantined());
        core::mem::forget(cpu.hash(b"secret")?);
        cpu.quarantine();
        cleared(&cpu);
        assert!(matches!(cpu.hash(b""), Err(Error::Quarantined)));
    }
    Ok(())
}
