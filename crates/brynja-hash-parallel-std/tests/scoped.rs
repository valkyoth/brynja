//! Scoped portable thread handoff and output lifecycle acceptance.
use brynja_hash_parallel::{
    self as hash, Fips202BitString, Fips202Output, ParallelHashError as Crypto,
    ParallelHashPublicDeclassification as Public, hardened_in_place as api,
};
use brynja_hash_parallel_std::{
    CancellationToken, ParallelHashExecutor as Executor, ParallelHashExecutorError as Error,
};

fn bits(bytes: &[u8], valid: u8) -> Result<Fips202BitString<'_>, Error> {
    Fips202BitString::new(bytes, valid).map_err(|_| Crypto::InvalidBitString.into())
}

macro_rules! cases {
    ($name:ident, $lifecycle:ident, $plan:ident, $workspace:ident, $with:ident, $with_bits:ident, $fixed:ident, $xof:ident) => {
        #[test]
        fn $name() -> Result<(), Error> {
            for workers in [1, 2, 4, 16] {
                let executor = Executor::new(workers, 128)?;
                let mut workspace = api::$workspace::new();
                for block in [1, 8, 17, 168] {
                    for valid in 1..=8 {
                        let mut input = [0x35; 19];
                        input[18] &= 0xff >> (8 - valid);
                        let input = bits(&input, valid)?;
                        let custom = bits(&[3], 2)?;
                        let plan = hash::$plan::new_bits(input, block)?;
                        let cancel = CancellationToken::new();
                        let mut expected = [0; 179];
                        let mut scratch = vec![0; block];
                        let mut fixed = hash::$fixed::new_bits(&mut scratch, custom)?;
                        fixed.finalize_bits(
                            input,
                            Fips202Output::new(&mut expected, valid)
                                .map_err(|_| Crypto::InvalidBitString)?,
                        )?;
                        let mut output = [0xa5; 179];
                        executor.$with_bits(&mut workspace, &plan, custom, &cancel, |root| {
                            root.finalize_public_bits(&mut output, valid, Public::acknowledge())
                        })??;
                        assert_eq!(output, expected);
                        let secret = executor.$with_bits(
                            &mut workspace,
                            &plan,
                            custom,
                            &cancel,
                            |root| root.finalize_secret_bits(&mut output, valid),
                        )??;
                        assert_eq!(secret.expose(), expected);
                        drop(secret);
                        assert_eq!(output, [0; 179]);
                        drop(fixed);
                        let mut xof = hash::$xof::new_bits(&mut scratch, custom)?;
                        xof.finalize_bits_xof(input)?.squeeze_final_bits(
                            Fips202Output::new(&mut expected, valid)
                                .map_err(|_| Crypto::InvalidBitString)?,
                        )?;
                        executor.$with_bits(&mut workspace, &plan, custom, &cancel, |root| {
                            root.finalize_xof()?.squeeze_final_bits_public(
                                &mut output,
                                valid,
                                Public::acknowledge(),
                            )
                        })??;
                        assert_eq!(output, expected);
                        let (prefix, suffix) = output.split_at_mut(169);
                        let secret = executor.$with_bits(
                            &mut workspace,
                            &plan,
                            custom,
                            &cancel,
                            |root| {
                                let mut reader = root.finalize_xof()?;
                                reader.squeeze_public(prefix, Public::acknowledge())?;
                                reader.squeeze_final_bits_secret(suffix, valid)
                            },
                        )??;
                        assert_eq!(prefix, &expected[..169]);
                        assert_eq!(secret.expose(), &expected[169..]);
                        drop(secret);
                        assert_eq!(suffix, [0; 10]);
                    }
                }
            }
            Ok(())
        }
        #[test]
        fn $lifecycle() -> Result<(), Error> {
            let executor = Executor::new(2, 8)?;
            let plan = hash::$plan::new(b"abc", 1)?;
            let empty = hash::$plan::new(b"", 1)?;
            let mut w = api::$workspace::new();
            let c = CancellationToken::new();
            let mut output = [0xa5; 9];
            c.cancel();
            let mut entered = false;
            assert_eq!(
                executor.$with(&mut w, &plan, b"", &c, |_| {
                    entered = true;
                }),
                Err(Error::Cancelled)
            );
            assert!(!entered);
            let small = Executor::new(2, 1)?;
            assert_eq!(
                small.$with(&mut w, &plan, b"", &CancellationToken::new(), |_| {
                    entered = true;
                }),
                Err(Error::WorkLimitExceeded)
            );
            assert!(!entered);
            let c = CancellationToken::new();
            for p in [&plan, &empty] {
                drop(
                    executor
                        .$with(&mut w, p, b"", &c, |root| root.finalize_secret(&mut output))??,
                );
                assert_eq!(output, [0; 9]);
                executor.$with(&mut w, p, b"", &c, |root| root.cancel())?;
                executor.$with(&mut w, p, b"", &c, |root| core::mem::forget(root))?;
                executor.$with(&mut w, p, b"", &c, |root| {
                    core::mem::forget(root.finalize_xof()?);
                    Ok::<_, Crypto>(())
                })??;
                for valid in [0, 9, 255] {
                    output.fill(0xa5);
                    assert!(
                        executor
                            .$with(&mut w, p, b"", &c, |root| root.finalize_public_bits(
                                &mut output,
                                valid,
                                Public::acknowledge()
                            ))?
                            .is_err()
                    );
                    assert_eq!(output, [0xa5; 9]);
                    assert!(
                        executor
                            .$with(&mut w, p, b"", &c, |root| root
                                .finalize_secret_bits(&mut output, valid))?
                            .is_err()
                    );
                    assert_eq!(output, [0; 9]);
                }
            }
            // The callback holds the executor gate; neither old nor new entry
            // points can allocate another worker batch on this same executor.
            executor.$with(&mut w, &plan, b"", &c, |root| {
                let mut other = api::$workspace::new();
                assert_eq!(
                    executor.$with(&mut other, &plan, b"", &c, |_| ()),
                    Err(Error::ResourceExhausted)
                );
                assert_eq!(
                    executor.parallel_hash128(b"", 1, b"", &mut [], &c),
                    Err(Error::ResourceExhausted)
                );
                root.cancel();
            })?;
            let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                executor.$with(&mut w, &plan, b"", &c, |root| {
                    core::mem::forget(root);
                    std::panic::resume_unwind(Box::new(()));
                })
            }));
            assert!(unwind.is_err());
            assert_eq!(
                executor.$with(&mut w, &plan, b"", &c, |_| ()),
                Err(Error::WorkerPanicked)
            );
            let fresh = Executor::new(2, 8)?;
            drop(fresh.$with(&mut w, &plan, b"", &c, |root| {
                root.finalize_secret(&mut output)
            })??);
            assert_eq!(output, [0; 9]);
            Ok(())
        }
    };
}
cases!(
    scoped_threaded128_matches_all_outputs,
    scoped_threaded128_lifecycle,
    ParallelHash128Plan,
    ParallelHash128CollectorWorkspace,
    with128,
    with128_bits,
    ParallelHash128,
    ParallelHashXof128
);
cases!(
    scoped_threaded256_matches_all_outputs,
    scoped_threaded256_lifecycle,
    ParallelHash256Plan,
    ParallelHash256CollectorWorkspace,
    with256,
    with256_bits,
    ParallelHash256,
    ParallelHashXof256
);
