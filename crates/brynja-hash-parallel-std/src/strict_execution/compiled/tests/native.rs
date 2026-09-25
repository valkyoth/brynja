use super::*;
use crate::strict_execution::tests::native::{guard, identities, reference};
fn root() -> Kernel {
    #[cfg(target_arch = "x86_64")]
    {
        Kernel::X86Keccak
    }
    #[cfg(target_arch = "aarch64")]
    {
        Kernel::ArmKeccak
    }
}
fn batch() -> BatchKernel {
    #[cfg(target_arch = "x86_64")]
    {
        BatchKernel::Avx2
    }
    #[cfg(target_arch = "aarch64")]
    {
        BatchKernel::Neon
    }
}
fn clear(s: &CompiledSession) {
    for data in [&s.inner.cvs, &s.inner.output, &s.inner.staging] {
        assert!(data.as_bytes().iter().all(|v| *v == 0));
    }
}
#[test]
fn actual_parallel_single_and_simd_waves_match_all_identities() -> Result<(), Error> {
    let _guard = guard();
    assert_eq!(root().check_compiled_target(), Ok(()));
    assert!(batch().compiled());
    for leaf_route in [LeafRoute::Single(root()), LeafRoute::Batch(batch())] {
        VECTOR_CALLS.store(0, std::sync::atomic::Ordering::Relaxed);
        let mut cases = 0;
        for algorithm in identities(257) {
            let mut session = CompiledSession::new(algorithm, root(), leaf_route, limits())?;
            for length in [0usize, 1, 31, 32, 33, 135, 136, 137, 1025] {
                for valid in 1u8..=8 {
                    let mut input = vec![0x37; length];
                    if let Some(last) = input.last_mut() {
                        *last &= u8::MAX >> (8 - valid);
                    }
                    let bits = || Bits {
                        bytes: &input,
                        valid_bits: if input.is_empty() { 0 } else { valid },
                    };
                    let custom = || Bits {
                        bytes: &[3],
                        valid_bits: 2,
                    };
                    let output =
                        session.compute(bits(), 32, custom(), &CancellationToken::new())?;
                    assert_eq!(output.expose(), reference(algorithm, bits(), 32, custom())?);
                    drop(output);
                    clear(&session);
                    cases += 1;
                }
            }
        }
        if matches!(leaf_route, LeafRoute::Batch(_)) {
            assert!(VECTOR_CALLS.load(std::sync::atomic::Ordering::Relaxed) > 0);
        }
        assert_eq!(cases, 288);
        println!("STRICT_PARALLELHASH: {leaf_route:?}; differential={cases}");
        for width in [0, 1, 7, 8, 32769] {
            for algorithm in identities(width) {
                let mut s = CompiledSession::new(algorithm, root(), leaf_route, limits())?;
                assert_eq!(
                    s.hash(b"abc", 1, b"custom")?.expose(),
                    reference(algorithm, Bits::bytes(b"abc"), 1, Bits::bytes(b"custom"))?
                );
                clear(&s);
            }
        }
    }
    Ok(())
}
#[test]
fn worker_root_faults_join_clear_and_classify_reuse() -> Result<(), Error> {
    let _guard = guard();
    for leaves in [LeafRoute::Single(root()), LeafRoute::Batch(batch())] {
        for algorithm in identities(257) {
            for point in [Point::Leaf(0), Point::Leaf(4), Point::Root, Point::Output] {
                for fault in [
                    Fault::Cancel(point),
                    Fault::Revoke(point),
                    Fault::Panic(point),
                ] {
                    let mut s = CompiledSession::new(algorithm, root(), leaves, limits())?;
                    s.fault = fault;
                    assert!(s.hash(&[0x74; 33], 1, b"custom").is_err());
                    clear(&s);
                    let terminal = !matches!(fault, Fault::Cancel(_));
                    assert_eq!(s.is_quarantined(), terminal);
                    s.fault = Fault::None;
                    if terminal {
                        assert!(matches!(s.hash(b"abc", 1, b""), Err(Error::Quarantined)));
                    } else {
                        drop(s.hash(b"abc", 1, b"")?);
                        clear(&s);
                    }
                }
            }
            let mut s = CompiledSession::new(algorithm, root(), leaves, limits())?;
            s.fault = Fault::Reorder;
            assert!(s.hash(&[0x35; 33], 1, b"").is_err());
            clear(&s);
            assert!(s.is_quarantined());
        }
    }
    Ok(())
}
#[test]
fn invalid_bits_limits_and_forgotten_outputs() -> Result<(), Error> {
    let _guard = guard();
    for leaves in [LeafRoute::Single(root()), LeafRoute::Batch(batch())] {
        let mut s =
            CompiledSession::new(Algorithm::ParallelHash256(257), root(), leaves, limits())?;
        core::mem::forget(s.hash(b"last secret", 1, b"")?);
        assert!(matches!(
            s.compute(
                Bits {
                    bytes: &[0xff],
                    valid_bits: 1
                },
                1,
                Bits::bytes(b""),
                &CancellationToken::new()
            ),
            Err(Error::InvalidBits)
        ));
        clear(&s);
        assert!(!s.is_quarantined());
        assert!(matches!(s.hash(b"a", 0, b""), Err(Error::WorkLimit)));
        assert!(matches!(s.hash(b"a", 4097, b""), Err(Error::WorkLimit)));
        core::mem::forget(s.hash(b"last secret", 1, b"")?);
        s.quarantine();
        clear(&s);
        assert!(matches!(s.hash(b"", 1, b""), Err(Error::Quarantined)));
    }
    Ok(())
}
