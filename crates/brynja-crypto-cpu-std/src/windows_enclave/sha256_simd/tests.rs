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
        input: &[Input<'_>; 8],
        output: Option<&mut [u8; 256]>,
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
    Plan::new([Algorithm::SHA256; 8])
}
fn input(data: &[u8]) -> [Input<'_>; 8] {
    core::array::from_fn(|_| Input::bytes(data))
}
#[test]
fn affine_retention_cancellation_forgetting_and_terminal_close() -> Result<(), Error> {
    let mut owner = Owner::new(Mock::default());
    owner.digest(plan()?, input(&[0; 64]), 100)?.cancel()?;
    assert_eq!(owner.state, State::Ready);
    let mut out = [0xa5; 256];
    owner
        .digest(plan()?, input(&[0; 1024]), 100)?
        .export(&mut out)?;
    assert_eq!(&out[..127], &[0x5a; 127]);
    assert_eq!(&out[127..], &[0; 129]);
    core::mem::forget(owner.digest(plan()?, input(&[0; 64]), 100)?);
    assert!(matches!(
        owner.digest(plan()?, input(&[0; 64]), 100),
        Err(Error::Busy)
    ));
    owner.close()?;
    owner.close()?;
    assert_eq!(owner.state, State::Closed);
    assert!(matches!(
        owner.digest(plan()?, input(&[0; 64]), 100),
        Err(Error::Quarantined)
    ));
    Ok(())
}
#[test]
fn rejection_unwind_abandonment_and_partial_output_fail_closed() -> Result<(), Error> {
    for unwind in [false, true] {
        let mut owner = Owner::new(Mock::default());
        let lease = owner.digest(plan()?, input(&[0; 64]), 100)?;
        lease.owner.transport.fail = !unwind;
        lease.owner.transport.panic = unwind;
        let mut out = [0xa5; 256];
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| lease.export(&mut out)));
        if unwind {
            assert!(result.is_err());
        } else {
            assert!(matches!(result, Ok(Err(Error::Protocol))));
        }
        assert_eq!(out, [0xa5; 256]);
        assert_eq!(owner.state, State::Quarantined);
        assert!(matches!(
            owner.digest(plan()?, input(&[0; 64]), 100),
            Err(Error::Quarantined)
        ));
    }
    let mut owner = Owner::new(Mock::default());
    drop(owner.digest(plan()?, input(&[0; 64]), 100)?);
    assert_eq!(owner.state, State::Quarantined);
    owner.transport.close_fail = true;
    assert_eq!(owner.close(), Err(Error::Release));
    assert_eq!(owner.state, State::Quarantined);
    Ok(())
}
#[test]
fn bounds_and_sequence_exhaustion_reject_before_transport() -> Result<(), Error> {
    for size in [0, 63, 1025] {
        let data = std::vec![0; size];
        let mut owner = Owner::new(Mock::default());
        assert!(matches!(
            owner.digest(plan()?, input(&data), 100),
            Err(Error::Bounds)
        ));
        assert_eq!(owner.state, State::Quarantined);
        assert_eq!(owner.transport.calls, 0);
    }
    for last in [0, 1, 7, 9] {
        let mut owner = Owner::new(Mock::default());
        let inputs = core::array::from_fn(|_| Input::bits(&[0; 64], last));
        assert!(matches!(
            owner.digest(plan()?, inputs, 100),
            Err(Error::Bounds)
        ));
        assert_eq!(owner.transport.calls, 0);
    }
    let mut owner = Owner::new(Mock::default());
    owner.sequence = u64::MAX;
    assert!(matches!(
        owner.digest(plan()?, input(&[0; 64]), 100),
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
    for last in [0, 9] {
        let mut owner = Owner::new(Mock::default());
        assert!(matches!(
            owner.digest(
                plan()?,
                core::array::from_fn(|_| Input::bits(&[0; 65], last)),
                100
            ),
            Err(Error::Bounds)
        ));
        assert_eq!(owner.transport.calls, 0);
    }
    Ok(())
}
#[test]
fn encoding_all_identities_and_operations() -> Result<(), Error> {
    for (algorithm, expected) in [(Algorithm::SHA224, 224), (Algorithm::SHA256, 256)] {
        assert_eq!(wire::identity(algorithm)?, expected);
        for op in [DIGEST, EXPORT, CANCEL] {
            let request = Request {
                op,
                sequence: 7,
                budget: 0,
                plan: Plan::new([algorithm; 8])?,
            };
            let data = [0; 65];
            let inputs = if op == DIGEST {
                core::array::from_fn(|_| Input::bits(&data, 7))
            } else {
                empty()
            };
            let bytes = request.header(&inputs)?;
            let words: std::vec::Vec<_> = bytes
                .chunks_exact(8)
                .map(|b| {
                    b.try_into()
                        .map(u64::from_le_bytes)
                        .map_err(|_| Error::Bounds)
                })
                .collect::<Result<_, _>>()?;
            assert_eq!(words.get(..4).ok_or(Error::Bounds)?, &[21, 7, 0, 2]);
            for lane in words.get(4..).ok_or(Error::Bounds)?.chunks_exact(4) {
                assert_eq!(lane.first(), Some(&if op == CANCEL { 0 } else { expected }));
                let descriptor = if op == DIGEST {
                    [65, 7, data.as_ptr() as usize as u64]
                } else {
                    [0; 3]
                };
                assert_eq!(lane.get(1..).ok_or(Error::Bounds)?, &descriptor);
            }
        }
    }
    for algorithm in [
        Algorithm::SHA384,
        Algorithm::SHA512,
        Algorithm::SHA512_224,
        Algorithm::SHA512_256,
        Algorithm::sha512_t(255)?,
    ] {
        assert!(Plan::new([algorithm; 8]).is_err());
    }
    for op in [0, 3, 99, 103] {
        assert!(
            Request {
                op,
                sequence: 1,
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
                sequence: 0,
                budget: 0,
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
            .header(&input(&[0; 64]))
            .is_err()
        );
    }
    assert_eq!(wire::PROTOCOL, 0x42524234);
    Ok(())
}
#[test]
fn copy_receipts_reject_counts_overlaps_and_stale_values() -> Result<(), Error> {
    for op in [DIGEST, EXPORT, CANCEL] {
        let good = [
            0x10100,
            0x11000,
            1,
            1,
            if op == DIGEST { 8 } else { 0 },
            usize::from(op == EXPORT),
            0,
        ];
        wire::receipt(0x10000, op, good)?;
        for i in 0..7 {
            let mut bad = good;
            let value = bad.get_mut(i).ok_or(Error::Bounds)?;
            *value = if i < 2 {
                0
            } else {
                value.checked_add(1).ok_or(Error::Bounds)?
            };
            assert!(wire::receipt(0x10000, op, bad).is_err());
        }
        let mut overlap = good;
        overlap[1] = good[0] + 287;
        assert!(wire::receipt(0x10000, op, overlap).is_err());
        let mut overrun = good;
        overrun[1] = 0x20000 - 8191;
        assert!(wire::receipt(0x10000, op, overrun).is_err());
        assert!(wire::receipt(usize::MAX, op, good).is_err());
    }
    for op in [0, 3] {
        wire::receipt(0, op, [0; 7])?;
        for i in 0..7 {
            let mut bad = [0; 7];
            *bad.get_mut(i).ok_or(Error::Bounds)? = 1;
            assert!(wire::receipt(0, op, bad).is_err());
        }
    }
    assert!(wire::receipt(0, 103, [0; 7]).is_err());
    Ok(())
}
