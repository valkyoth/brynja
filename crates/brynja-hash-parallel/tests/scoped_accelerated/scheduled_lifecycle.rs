use super::*;

macro_rules! check {
    ($test:ident, $workspace:ident, $leaf_workspace:ident, $plan:ident, $size:expr) => {
        #[test]
        fn $test() -> Result<(), Box<dyn std::error::Error>> {
            let Some(root_owner) = owner()? else {
                return Ok(());
            };
            let Some(leaf_owner) = owner()? else {
                return Ok(());
            };
            let run = || -> Result<(), Error> {
                let plan = hash::$plan::new(b"first second", 8)?;
                let wrong = hash::$plan::new(b"first second", 8)?;
                let mut workspace = api::$workspace::new(session(&root_owner)?)?;
                let mut worker = api::$leaf_workspace::new(session(&leaf_owner)?)?;
                let mut scratch = [0xa5; 200];
                let mut leaf = [0xa5; $size];
                for mode in 0..4 {
                    let mut output = [0xa5; 32];
                    workspace.with_scratch(&plan, b"", &mut scratch, |mut root| {
                        match mode {
                            0 => assert_eq!(
                                root.merge(worker.execute(wrong.job(0)?, &mut leaf)?),
                                Err(Error::LeafIdentity)
                            ),
                            1 => assert_eq!(
                                root.merge(worker.execute(plan.job(1)?, &mut leaf)?),
                                Err(Error::LeafOrder)
                            ),
                            2 => {
                                root.merge(worker.execute(plan.job(0)?, &mut leaf)?)?;
                                assert_eq!(
                                    root.merge(worker.execute(plan.job(0)?, &mut leaf)?),
                                    Err(Error::LeafOrder)
                                );
                            }
                            _ => {
                                root.merge(worker.execute(plan.job(0)?, &mut leaf)?)?;
                                assert!(root.finalize_secret(&mut output).is_err());
                                return Ok::<(), Error>(());
                            }
                        }
                        assert_eq!(leaf, [0; $size]);
                        assert!(
                            root.merge(worker.execute(plan.job(0)?, &mut leaf)?)
                                .is_err()
                        );
                        assert!(root.finalize_secret(&mut output).is_err());
                        Ok(())
                    })??;
                    assert_eq!(output, [0; 32]);
                    assert_eq!(scratch, [0; 200]);
                }
                for action in 0..6 {
                    let caught = catch_unwind(AssertUnwindSafe(|| -> Result<(), Error> {
                        workspace.with_scratch(&plan, b"", &mut scratch, |mut root| {
                            root.merge(worker.execute(plan.job(0)?, &mut leaf)?)?;
                            if action == 0 {
                                root.cancel();
                            } else if action == 1 {
                                core::mem::forget(root);
                            } else if action == 2 {
                                panic!("root unwind");
                            } else {
                                root.merge(worker.execute(plan.job(1)?, &mut leaf)?)?;
                                let mut reader = root.finalize_xof()?;
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
                        assert!(caught.is_err());
                    } else {
                        caught.map_err(|_| Error::StateConsumed)??;
                    }
                    assert_eq!(scratch, [0; 200]);
                    assert_eq!(leaf, [0; $size]);
                    assert_eq!(workspace.report().health, Health::Healthy);
                    assert_eq!(worker.report().health, Health::Healthy);
                }
                let empty = hash::$plan::new(b"", 8)?;
                for valid in [0, 9, 255] {
                    let mut output = [0xa5; 3];
                    assert!(
                        workspace
                            .with(&empty, b"", |root| root.finalize_public_bits(
                                &mut output,
                                valid,
                                Public::acknowledge()
                            ))?
                            .is_err()
                    );
                    assert_eq!(output, [0xa5; 3]);
                    assert!(
                        workspace
                            .with(&empty, b"", |root| root
                                .finalize_secret_bits(&mut output, valid))?
                            .is_err()
                    );
                    assert_eq!(output, [0; 3]);
                }
                let mut wide = [0xa5; 169];
                assert!(
                    workspace
                        .with(&empty, b"", |root| root
                            .finalize_public(&mut wide, Public::acknowledge()))?
                        .is_err()
                );
                assert_eq!(wide, [0xa5; 169]);
                workspace.with(&empty, b"", |root| {
                    let mut reader = root.finalize_xof()?;
                    assert!(
                        reader
                            .squeeze_public(&mut wide, Public::acknowledge())
                            .is_err()
                    );
                    assert_eq!(wide, [0xa5; 169]);
                    assert!(reader.squeeze_secret(&mut wide).is_err());
                    assert_eq!(wide, [0; 169]);
                    Ok::<(), Error>(())
                })??;
                drop(workspace.with_scratch(&empty, b"", &mut [], |root| {
                    root.finalize_secret(&mut wide)
                })??);
                assert_eq!(wide, [0; 169]);
                Ok(())
            };
            run().map_err(|e| format!("scoped scheduled lifecycle: {e:?}"))?;
            for phase in 0..6 {
                let Some(root_owner) = owner()? else {
                    return Ok(());
                };
                let Some(leaf_owner) = owner()? else {
                    return Ok(());
                };
                let run = || -> Result<(), Error> {
                    let plan = hash::$plan::new(b"one", 8)?;
                    let mut w = api::$workspace::new(session(&root_owner)?)?;
                    let mut worker = api::$leaf_workspace::new(session(&leaf_owner)?)?;
                    let mut leaf = [0xa5; $size];
                    let mut scratch = [0xa5; 64];
                    let mut output = [0xa5; 32];
                    if phase == 0 {
                        root_owner.quarantine();
                        let mut entered = false;
                        assert!(
                            w.with_scratch(&plan, b"", &mut scratch, |_| entered = true)
                                .is_err()
                        );
                        assert!(!entered);
                        assert_eq!(scratch, [0; 64]);
                        return Ok(());
                    }
                    if phase == 1 {
                        leaf_owner.quarantine();
                        assert!(worker.execute(plan.job(0)?, &mut leaf).is_err());
                        assert_eq!(leaf, [0; $size]);
                        return Ok(());
                    }
                    let result = worker.execute(plan.job(0)?, &mut leaf)?;
                    // Revoking a completed worker does not revoke the root.
                    leaf_owner.quarantine();
                    w.with_scratch(&plan, b"", &mut scratch, |mut root| {
                        if phase == 2 {
                            root_owner.quarantine();
                            assert!(root.merge(result).is_err());
                            assert!(root.finalize_secret(&mut output).is_err());
                            assert_eq!(output, [0; 32]);
                        } else {
                            root.merge(result)?;
                            if phase == 3 {
                                root_owner.quarantine();
                                assert!(
                                    root.finalize_public(&mut output, Public::acknowledge())
                                        .is_err()
                                );
                                assert_eq!(output, [0xa5; 32]);
                            } else {
                                let mut reader = root.finalize_xof()?;
                                reader.squeeze_public(&mut output, Public::acknowledge())?;
                                root_owner.quarantine();
                                if phase == 4 {
                                    output.fill(0xa5);
                                    assert!(
                                        reader
                                            .squeeze_public(&mut output, Public::acknowledge())
                                            .is_err()
                                    );
                                    assert_eq!(output, [0xa5; 32]);
                                } else {
                                    assert!(
                                        reader
                                            .squeeze_public(&mut [], Public::acknowledge())
                                            .is_err()
                                    );
                                }
                                assert!(reader.squeeze_secret(&mut output).is_err());
                                assert_eq!(output, [0; 32]);
                            }
                        }
                        Ok::<(), Error>(())
                    })??;
                    assert_eq!(leaf, [0; $size]);
                    assert_eq!(scratch, [0; 64]);
                    assert!(w.with(&plan, b"", |_| ()).is_err());
                    assert!(worker.execute(plan.job(0)?, &mut leaf).is_err());
                    assert_eq!(leaf, [0; $size]);
                    Ok(())
                };
                run().map_err(|e| format!("scoped scheduled revocation: {e:?}"))?;
            }
            Ok(())
        }
    };
}
check!(
    scoped_scheduled_accelerated128_lifecycle,
    ParallelHash128CollectorWorkspace,
    ParallelHash128LeafWorkspace,
    ParallelHash128Plan,
    32
);
check!(
    scoped_scheduled_accelerated256_lifecycle,
    ParallelHash256CollectorWorkspace,
    ParallelHash256LeafWorkspace,
    ParallelHash256Plan,
    64
);
