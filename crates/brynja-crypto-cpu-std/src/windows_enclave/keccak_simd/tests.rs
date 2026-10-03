use super::*;
#[cfg(all(
    target_os = "windows",
    target_arch = "x86_64",
    target_env = "msvc",
    not(miri),
    not(kani)
))]
mod native;
#[derive(Default)]
struct Mock {
    calls: usize,
    fail: bool,
    panic: bool,
    close_fail: bool,
}
impl Channel for Mock {
    fn request(
        &mut self,
        r: Request,
        input: &[Input<'_>; 4],
        output: Option<&mut [u8; 1024]>,
    ) -> Result<(), Error> {
        r.header(input)?;
        self.calls = self.calls.checked_add(1).ok_or(Error::Exhausted)?;
        if let Some(out) = output {
            out[..127].fill(0x5a);
        }
        assert!(!self.panic, "injected unwind");
        if self.fail {
            Err(Error::Protocol)
        } else {
            Ok(())
        }
    }
    fn close(&mut self) -> Result<(), Error> {
        if self.close_fail {
            Err(Error::Release)
        } else {
            Ok(())
        }
    }
}
fn plan() -> Result<Plan, Error> {
    Plan::new(
        [Slot {
            algorithm: Algorithm::Sha3_256,
            output_bits: 256,
        }; 4],
    )
}
fn input(data: &[u8]) -> [Input<'_>; 4] {
    core::array::from_fn(|_| Input::bytes(data))
}
#[test]
fn affine_retention_cancellation_forgetting_and_terminal_close() -> Result<(), Error> {
    let mut owner = Owner::new(Mock::default());
    owner.digest(plan()?, input(&[0; 128]), 100)?.cancel()?;
    assert_eq!(owner.state, State::Ready);
    let mut out = [0xa5; 1024];
    owner
        .digest(plan()?, input(&[0; 1024]), 100)?
        .export(&mut out)?;
    assert_eq!(&out[..127], &[0x5a; 127]);
    assert_eq!(&out[127..], &[0; 897]);
    core::mem::forget(owner.digest(plan()?, input(&[0; 128]), 100)?);
    assert!(matches!(
        owner.digest(plan()?, input(&[0; 128]), 100),
        Err(Error::Busy)
    ));
    owner.close()?;
    owner.close()?;
    assert_eq!(owner.state, State::Closed);
    assert!(matches!(
        owner.digest(plan()?, input(&[0; 128]), 100),
        Err(Error::Quarantined)
    ));
    Ok(())
}
#[test]
fn rejection_unwind_abandonment_and_partial_output_fail_closed() -> Result<(), Error> {
    for unwind in [false, true] {
        let mut owner = Owner::new(Mock::default());
        let lease = owner.digest(plan()?, input(&[0; 128]), 100)?;
        lease.owner.transport.fail = !unwind;
        lease.owner.transport.panic = unwind;
        let mut out = [0xa5; 1024];
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| lease.export(&mut out)));
        if unwind {
            assert!(result.is_err());
        } else {
            assert!(matches!(result, Ok(Err(Error::Protocol))));
        }
        assert_eq!(out, [0xa5; 1024]);
        assert_eq!(owner.state, State::Quarantined);
        assert!(matches!(
            owner.digest(plan()?, input(&[0; 128]), 100),
            Err(Error::Quarantined)
        ));
    }
    let mut owner = Owner::new(Mock::default());
    drop(owner.digest(plan()?, input(&[0; 128]), 100)?);
    assert_eq!(owner.state, State::Quarantined);
    owner.transport.close_fail = true;
    assert_eq!(owner.close(), Err(Error::Release));
    assert_eq!(owner.state, State::Quarantined);
    Ok(())
}

#[test]
fn bounds_and_sequence_exhaustion_reject_before_transport() -> Result<(), Error> {
    for part in 0..3 {
        for (size, last) in [(1025, 8), (1, 0), (1, 9), (0, 8)] {
            let data = std::vec![0; size];
            let mut owner = Owner::new(Mock::default());
            let inputs = core::array::from_fn(|_| {
                let mut i = Input::bytes(&[]);
                let p = Part::bits(&data, last);
                match part {
                    0 => i.message = p,
                    1 => i.name = p,
                    _ => i.customization = p,
                }
                i
            });
            let p = Plan::new(
                [Slot {
                    algorithm: Algorithm::Cshake128,
                    output_bits: 7,
                }; 4],
            )?;
            assert!(matches!(owner.digest(p, inputs, 100), Err(Error::Bounds)));
            assert_eq!(owner.state, State::Quarantined);
            assert_eq!(owner.transport.calls, 0);
        }
    }
    for algorithm in [
        Algorithm::Sha3_224,
        Algorithm::Sha3_256,
        Algorithm::Sha3_384,
        Algorithm::Sha3_512,
        Algorithm::Shake128,
        Algorithm::Shake256,
    ] {
        for part in 1..=2 {
            let mut owner = Owner::new(Mock::default());
            let inputs = core::array::from_fn(|_| {
                let mut i = Input::bytes(&[]);
                if part == 1 {
                    i.name = Part::bytes(b"a");
                } else {
                    i.customization = Part::bytes(b"a");
                }
                i
            });
            let p = Plan::new(
                [Slot {
                    algorithm,
                    output_bits: algorithm.width().map_or(7, |n| n * 8),
                }; 4],
            )?;
            assert!(matches!(owner.digest(p, inputs, 100), Err(Error::Bounds)));
            assert_eq!(owner.transport.calls, 0);
        }
    }
    let mut owner = Owner::new(Mock::default());
    owner.sequence = u64::MAX;
    assert!(matches!(
        owner.digest(plan()?, empty(), 100),
        Err(Error::Exhausted)
    ));
    assert_eq!(owner.state, State::Quarantined);
    assert_eq!(owner.transport.calls, 0);
    for state in [State::Quarantined, State::Closed] {
        let mut owner = Owner::new(Mock::default());
        owner.state = state;
        assert_eq!(
            owner.issue(CANCEL, plan()?, 0, &empty(), None),
            Err(Error::Quarantined)
        );
        assert_eq!(owner.transport.calls, 0);
    }
    for algorithm in [
        Algorithm::Sha3_224,
        Algorithm::Sha3_256,
        Algorithm::Sha3_384,
        Algorithm::Sha3_512,
        Algorithm::Shake128,
        Algorithm::Shake256,
        Algorithm::Cshake128,
        Algorithm::Cshake256,
    ] {
        assert_eq!(
            Plan::new(
                [Slot {
                    algorithm,
                    output_bits: 2049
                }; 4]
            ),
            Err(Error::Bounds)
        );
        if let Some(n) = algorithm.width() {
            for bits in [0, n * 8 - 1, n * 8 + 1] {
                assert_eq!(
                    Plan::new(
                        [Slot {
                            algorithm,
                            output_bits: bits
                        }; 4]
                    ),
                    Err(Error::Bounds)
                );
            }
        }
    }
    Ok(())
}
#[test]
fn encoding_all_identities_operations_and_sparse_payloads() -> Result<(), Error> {
    let algorithms = [
        Algorithm::Sha3_224,
        Algorithm::Sha3_256,
        Algorithm::Sha3_384,
        Algorithm::Sha3_512,
        Algorithm::Shake128,
        Algorithm::Shake256,
        Algorithm::Cshake128,
        Algorithm::Cshake256,
    ];
    for (i, algorithm) in algorithms.into_iter().enumerate() {
        let bits = algorithm.width().map_or(2047, |n| n * 8);
        let plan = Plan::new(
            [Slot {
                algorithm,
                output_bits: bits,
            }; 4],
        )?;
        for op in [DIGEST, EXPORT, CANCEL] {
            let input = if op == DIGEST {
                core::array::from_fn(|lane| {
                    Input::new(
                        Part::bits(b"a", 7),
                        if i >= 6 && lane % 2 == 0 {
                            Part::bits(b"b", 7)
                        } else {
                            Part::bytes(&[])
                        },
                        if i >= 6 && lane % 2 == 1 {
                            Part::bits(b"c", 7)
                        } else {
                            Part::bytes(&[])
                        },
                    )
                })
            } else {
                empty()
            };
            let r = Request {
                op,
                sequence: 7,
                budget: 0,
                plan,
            };
            let header = r.header(&input)?;
            let words = header
                .chunks_exact(8)
                .map(|b| {
                    b.try_into()
                        .map(u64::from_le_bytes)
                        .map_err(|_| Error::Bounds)
                })
                .collect::<Result<std::vec::Vec<_>, _>>()?;
            assert_eq!(words.get(..4).ok_or(Error::Bounds)?, &[22, 7, 0, 2]);
            for (f, input) in words
                .get(4..)
                .ok_or(Error::Bounds)?
                .chunks_exact(11)
                .zip(&input)
            {
                let expected = if op == CANCEL {
                    [0, 0]
                } else {
                    [i as u64 + 1, bits as u64]
                };
                assert_eq!(f.get(..2).ok_or(Error::Bounds)?, &expected);
                for (triple, part) in f.get(2..).ok_or(Error::Bounds)?.chunks_exact(3).zip([
                    &input.message,
                    &input.name,
                    &input.customization,
                ]) {
                    let want = if part.bytes.is_empty() {
                        [0; 3]
                    } else {
                        [1, 7, part.bytes.as_ptr() as usize as u64]
                    };
                    assert_eq!(triple, &want);
                }
            }
            assert_eq!(
                wire::payload_count(&input),
                if op != DIGEST {
                    0
                } else if i >= 6 {
                    8
                } else {
                    4
                }
            );
        }
    }
    for op in [DIGEST, EXPORT, CANCEL] {
        assert!(
            Request {
                op,
                sequence: 0,
                budget: 0,
                plan: plan()?
            }
            .header(&empty())
            .is_err()
        );
    }
    for op in [EXPORT, CANCEL] {
        assert!(
            Request {
                op,
                sequence: 1,
                budget: 1,
                plan: plan()?
            }
            .header(&empty())
            .is_err()
        );
        assert!(
            Request {
                op,
                sequence: 1,
                budget: 0,
                plan: plan()?
            }
            .header(&input(b"x"))
            .is_err()
        );
    }
    assert!(
        Request {
            op: 103,
            sequence: 1,
            budget: 0,
            plan: plan()?
        }
        .header(&empty())
        .is_err()
    );
    assert_eq!(wire::PROTOCOL, 0x42524235);
    Ok(())
}
#[test]
fn copy_receipts_reject_counts_overlaps_and_stale_values() -> Result<(), Error> {
    for op in [DIGEST, EXPORT, CANCEL] {
        for n in 0..=12 {
            if op != DIGEST && n != 0 {
                continue;
            }
            let good = [0x10100, 0x11000, 1, 1, n, usize::from(op == EXPORT), 0];
            wire::receipt(0x10000, op, n, good)?;
            for i in 0..7 {
                let mut bad = good;
                let value = bad.get_mut(i).ok_or(Error::Bounds)?;
                *value = if i < 2 {
                    0
                } else {
                    value.checked_add(1).ok_or(Error::Bounds)?
                };
                assert!(wire::receipt(0x10000, op, n, bad).is_err());
            }
            let mut overlap = good;
            overlap[1] = good[0] + 383;
            assert!(wire::receipt(0x10000, op, n, overlap).is_err());
            let mut overrun = good;
            overrun[1] = 0x20000 - 12287;
            assert!(wire::receipt(0x10000, op, n, overrun).is_err());
            assert!(wire::receipt(usize::MAX, op, n, good).is_err());
        }
    }
    for op in [0, 3] {
        wire::receipt(0, op, 0, [0; 7])?;
        for i in 0..7 {
            let mut bad = [0; 7];
            *bad.get_mut(i).ok_or(Error::Bounds)? = 1;
            assert!(wire::receipt(0, op, 0, bad).is_err());
        }
        assert!(wire::receipt(0, op, 1, [0; 7]).is_err());
    }
    assert!(wire::receipt(0x10000, DIGEST, 13, [0x10100, 0x11000, 1, 1, 13, 0, 0]).is_err());
    assert!(wire::receipt(0x10000, CANCEL, 1, [0x10100, 0x11000, 1, 1, 1, 0, 0]).is_err());
    assert!(wire::receipt(0, 103, 0, [0; 7]).is_err());
    Ok(())
}
