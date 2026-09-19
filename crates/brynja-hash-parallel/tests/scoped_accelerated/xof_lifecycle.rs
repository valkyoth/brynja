use super::*;

macro_rules! lifecycle {
    ($test:ident, $workspace:ident) => {
        #[test]
        fn $test() -> Result<(), Box<dyn std::error::Error>> {
            let Some(root) = owner()? else {
                return Ok(());
            };
            let Some(leaf) = owner()? else {
                return Ok(());
            };
            let run = || -> Result<(), Error> {
                let mut workspace = api::$workspace::new(session(&root)?, session(&leaf)?)?;
                let mut block = [0xa5; 8];
                let mut scratch = [0xa5; 200];
                let mut expected = [0; 32];
                workspace.with(&mut block, b"", |state| {
                    state
                        .finalize_xof()?
                        .squeeze_public(&mut expected, Public::acknowledge())
                })??;
                for action in 0..6 {
                    let result = catch_unwind(AssertUnwindSafe(|| -> Result<(), Error> {
                        workspace.with_scratch(&mut block, b"", &mut scratch, |mut state| {
                            state.update(b"secret pending bytes")?;
                            if action == 0 {
                                state.cancel();
                            } else if action == 1 {
                                core::mem::forget(state);
                            } else if action == 2 {
                                panic!("absorbing unwind");
                            } else {
                                let mut reader = state.finalize_xof()?;
                                drop(reader.squeeze_secret(&mut [0; 179])?);
                                if action == 3 {
                                    reader.cancel();
                                } else if action == 4 {
                                    core::mem::forget(reader);
                                } else {
                                    panic!("reader unwind");
                                }
                            }
                            Ok::<(), Error>(())
                        })?
                    }));
                    if action == 2 || action == 5 {
                        assert!(result.is_err());
                    } else {
                        result.map_err(|_| Error::StateConsumed)??;
                    }
                    assert_eq!(block, [0; 8]);
                    assert_eq!(scratch, [0; 200]);
                    assert_eq!(root.report().health, Health::Healthy);
                    assert_eq!(leaf.report().health, Health::Healthy);
                    let mut actual = [0xa5; 32];
                    workspace.with(&mut block, b"", |state| {
                        state
                            .finalize_xof()?
                            .squeeze_public(&mut actual, Public::acknowledge())
                    })??;
                    assert_eq!(actual, expected);
                }
                // Staging bounds each public read, not the total XOF stream.
                workspace.with(&mut block, b"", |state| {
                    let mut reader = state.finalize_xof()?;
                    for _ in 0..3 {
                        reader.squeeze_public(&mut [0; 168], Public::acknowledge())?;
                    }
                    let mut output = [0xa5; 169];
                    assert!(
                        reader
                            .squeeze_public(&mut output, Public::acknowledge())
                            .is_err()
                    );
                    assert_eq!(output, [0xa5; 169]);
                    assert!(
                        reader
                            .squeeze_public(&mut [], Public::acknowledge())
                            .is_err()
                    );
                    assert!(reader.squeeze_secret(&mut output).is_err());
                    assert_eq!(output, [0; 169]);
                    Ok::<(), Error>(())
                })??;
                // Secret output is not limited by an empty public stage.
                let secret = workspace.with_scratch(&mut block, b"", &mut [], |state| {
                    state
                        .finalize_xof()?
                        .squeeze_final_bits_secret(&mut scratch, 8)
                })??;
                assert_eq!(
                    secret.expose().get(..32).ok_or(Error::StateConsumed)?,
                    &expected
                );
                drop(secret);
                assert_eq!(scratch, [0; 200]);
                let mut same = api::$workspace::new(session(&root)?, session(&root)?)?;
                same.with(&mut block, b"", |state| {
                    state
                        .finalize_xof()?
                        .squeeze_public(&mut scratch[..32], Public::acknowledge())
                })??;
                assert_eq!(&scratch[..32], &expected);
                Ok(())
            };
            run().map_err(|e| format!("scoped XOF lifecycle: {e:?}"))?;
            // Both authorities matter before completion. After completion only
            // root authority governs reads; no more leaf work can occur.
            for root_revoke in [false, true] {
                for after_finish in [false, true] {
                    for operation in 0..5 {
                        let Some(root) = owner()? else {
                            return Ok(());
                        };
                        let Some(leaf) = owner()? else {
                            return Ok(());
                        };
                        let run = || -> Result<(), Error> {
                            let mut w = api::$workspace::new(session(&root)?, session(&leaf)?)?;
                            let mut block = [0xa5; 8];
                            let mut scratch = [0xa5; 64];
                            w.with_scratch(&mut block, b"", &mut scratch, |mut state| {
                                state.update(b"pending")?;
                                if !after_finish {
                                    if root_revoke {
                                        root.quarantine();
                                    } else {
                                        leaf.quarantine();
                                    }
                                    assert!(state.finalize_xof().is_err());
                                    return Ok::<(), Error>(());
                                }
                                let mut reader = state.finalize_xof()?;
                                if root_revoke {
                                    root.quarantine();
                                } else {
                                    leaf.quarantine();
                                }
                                let mut output = [0xa5; 32];
                                if !root_revoke {
                                    // Completed leaf revocation cannot authorize fallback,
                                    // nor revoke the separately owned live root.
                                    reader.squeeze_public(&mut output, Public::acknowledge())?;
                                    let mut reference = hash::hardened_in_place::$workspace::new();
                                    let mut expected = [0; 32];
                                    reference.with(&mut [0; 8], b"", |mut state| {
                                        state.update(b"pending")?;
                                        state
                                            .finalize_xof()?
                                            .squeeze_public(&mut expected, Public::acknowledge())
                                    })??;
                                    assert_eq!(output, expected);
                                } else {
                                    match operation {
                                        0 => assert!(
                                            reader
                                                .squeeze_public(&mut [], Public::acknowledge())
                                                .is_err()
                                        ),
                                        1 => {
                                            assert!(
                                                reader
                                                    .squeeze_public(
                                                        &mut output,
                                                        Public::acknowledge()
                                                    )
                                                    .is_err()
                                            );
                                            assert_eq!(output, [0xa5; 32]);
                                        }
                                        2 => {
                                            assert!(reader.squeeze_secret(&mut output).is_err());
                                            assert_eq!(output, [0; 32]);
                                        }
                                        3 => {
                                            assert!(
                                                reader
                                                    .squeeze_final_bits_public(
                                                        &mut output,
                                                        3,
                                                        Public::acknowledge()
                                                    )
                                                    .is_err()
                                            );
                                            assert_eq!(output, [0xa5; 32]);
                                            return Ok(());
                                        }
                                        _ => {
                                            assert!(
                                                reader
                                                    .squeeze_final_bits_secret(&mut output, 3)
                                                    .is_err()
                                            );
                                            assert_eq!(output, [0; 32]);
                                            return Ok(());
                                        }
                                    }
                                    assert!(
                                        reader
                                            .squeeze_public(&mut [], Public::acknowledge())
                                            .is_err()
                                    );
                                    output.fill(0xa5);
                                    assert!(reader.squeeze_secret(&mut output).is_err());
                                    assert_eq!(output, [0; 32]);
                                }
                                Ok(())
                            })??;
                            assert_eq!(block, [0; 8]);
                            assert_eq!(scratch, [0; 64]);
                            assert!(w.with(&mut block, b"", |_| ()).is_err());
                            Ok(())
                        };
                        run().map_err(|e| format!("scoped XOF revocation: {e:?}"))?;
                    }
                }
            }
            Ok(())
        }
    };
}
lifecycle!(
    scoped_accelerated_xof128_lifecycle,
    ParallelHashXof128Workspace
);
lifecycle!(
    scoped_accelerated_xof256_lifecycle,
    ParallelHashXof256Workspace
);
