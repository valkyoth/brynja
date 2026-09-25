use super::*;
fn kernels() -> Vec<Kernel> {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    assert_eq!(Kernel::X86Keccak.check_compiled_target(), Ok(()));
    #[cfg(all(
        target_arch = "aarch64",
        target_feature = "neon",
        target_feature = "sha3"
    ))]
    assert_eq!(Kernel::ArmKeccak.check_compiled_target(), Ok(()));
    [Kernel::X86Keccak, Kernel::ArmKeccak]
        .into_iter()
        .filter(|k| k.check_compiled_target().is_ok())
        .collect()
}
fn algorithms(bits: usize) -> [Algorithm; 4] {
    [
        Algorithm::TupleHash128(bits),
        Algorithm::TupleHash256(bits),
        Algorithm::TupleHashXof128(bits),
        Algorithm::TupleHashXof256(bits),
    ]
}
fn clear(session: &CompiledSession) {
    assert!(session.inner.output.as_bytes().iter().all(|b| *b == 0));
    assert!(session.inner.staging.as_bytes().iter().all(|b| *b == 0));
}
#[test]
fn native_tuple_boundaries_bits_item_identity_and_protected_storage() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    for kernel in kernels() {
        let mut count = 0;
        for width in [0, 1, 256, 257, 32777] {
            for algorithm in algorithms(width) {
                let mut compiled = CompiledSession::new(algorithm, kernel, limits())?;
                let mut scalar = Session::new(algorithm, limits())?;
                for length in [0, 1, 135, 136, 167, 168, 4097] {
                    let input = vec![0x93; length];
                    for valid in 1..=8 {
                        let last = [0x5a >> (8 - valid)];
                        let (first, last_chunk) =
                            input.split_at_checked(length / 2).ok_or(Error::Invariant)?;
                        let chunks: &[&[u8]] = &[first, &[], last_chunk];
                        let items = [
                            Item::bytes(b""),
                            Item {
                                chunks,
                                tail: Bits {
                                    bytes: &last,
                                    valid_bits: valid,
                                },
                            },
                            Item::bytes(b"last"),
                        ];
                        let custom = || Bits {
                            bytes: &[3],
                            valid_bits: 2,
                        };
                        let actual = compiled.compute(&items, custom(), &Cancellation::new())?;
                        let expected = scalar.compute(&items, custom(), &Cancellation::new())?;
                        assert_eq!(actual.expose(), expected.expose());
                        drop(actual);
                        drop(expected);
                        clear(&compiled);
                        count += 1;
                    }
                }
                for items in [
                    &[][..],
                    &[Item::bytes(b"")][..],
                    &[Item::bytes(b"ab"), Item::bytes(b"c")][..],
                    &[Item::bytes(b"a"), Item::bytes(b"bc")][..],
                ] {
                    let actual = compiled.hash(items, b"")?;
                    let expected = scalar.hash(items, b"")?;
                    assert_eq!(actual.expose(), expected.expose());
                }
            }
        }
        assert_eq!(count, 1120);
        println!("STRICT_TUPLEHASH_COMPILED: {kernel:?}; differential={count}");
    }
    Ok(())
}
#[test]
fn cancellation_revocation_writer_failure_and_unwind_are_transactional() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    for kernel in kernels() {
        for algorithm in algorithms(65543) {
            let items = [Item::bytes(b"secret item")];
            for point in [
                Boundary::Setup,
                Boundary::Item,
                Boundary::Update,
                Boundary::Complete,
                Boundary::Finalize,
                Boundary::Output,
            ] {
                for fault in [
                    Fault::Cancel(point),
                    Fault::Revoke(point),
                    Fault::Panic(point),
                ] {
                    let mut s = CompiledSession::new(algorithm, kernel, limits())?;
                    s.fault = fault;
                    assert!(
                        s.compute(&items, Bits::empty(), &Cancellation::new())
                            .is_err()
                    );
                    clear(&s);
                    let terminal = !matches!(fault, Fault::Cancel(_));
                    assert_eq!(s.is_quarantined(), terminal);
                    s.fault = Fault::None;
                    if terminal {
                        assert!(matches!(s.hash(&[], b""), Err(Error::Quarantined)));
                    } else {
                        drop(s.hash(&items, b"")?);
                    }
                    clear(&s);
                }
            }
            let mut s = CompiledSession::new(algorithm, kernel, limits())?;
            s.fault = Fault::WrongLength;
            assert!(matches!(
                s.hash(&items, b""),
                Err(Error::Execution(
                    brynja_hash_tuple::TupleHashError::IncompleteItem
                ))
            ));
            assert!(s.is_quarantined());
            clear(&s);
            if algorithm.xof() {
                for fault in [
                    Fault::CancelSecondOutput,
                    Fault::RevokeSecondOutput,
                    Fault::PanicSecondOutput,
                ] {
                    let mut s = CompiledSession::new(algorithm, kernel, limits())?;
                    s.fault = fault;
                    assert!(s.hash(&items, b"").is_err());
                    assert_eq!(
                        s.is_quarantined(),
                        !matches!(fault, Fault::CancelSecondOutput)
                    );
                    clear(&s);
                }
            }
        }
    }
    Ok(())
}
#[test]
fn invalid_contents_limits_forgotten_output_and_quarantine() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    for kernel in kernels() {
        for algorithm in algorithms(257) {
            let mut s = CompiledSession::new(algorithm, kernel, limits())?;
            let bad = || Bits {
                bytes: &[0xff],
                valid_bits: 1,
            };
            assert!(matches!(
                s.compute(&[], bad(), &Cancellation::new()),
                Err(Error::InvalidBits)
            ));
            assert!(matches!(
                s.hash(
                    &[Item {
                        chunks: &[],
                        tail: bad()
                    }],
                    b""
                ),
                Err(Error::InvalidBits)
            ));
            assert!(!s.is_quarantined());
            clear(&s);
            s.inner.limits.max_items = 0;
            assert!(matches!(
                s.hash(&[Item::bytes(b"")], b""),
                Err(Error::WorkLimit)
            ));
            s.inner.limits = limits();
            let cancelled = Cancellation::new();
            cancelled.cancel();
            assert!(matches!(
                s.compute(&[], Bits::empty(), &cancelled),
                Err(Error::Cancelled)
            ));
            assert!(!s.is_quarantined());
            core::mem::forget(s.hash(&[Item::bytes(b"secret")], b"")?);
            assert!(s.inner.output.as_bytes().iter().any(|b| *b != 0));
            s.quarantine();
            clear(&s);
            assert!(matches!(s.hash(&[], b""), Err(Error::Quarantined)));
        }
    }
    Ok(())
}
