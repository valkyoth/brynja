use super::*;
use crate::{Fips202Output, ParallelHashError};

macro_rules! check {
    ($test:ident, $lifecycle:ident, $workspace:ident, $plan:ident, $fixed:ident, $xof:ident, $size:expr) => {
        #[test]
        fn $test() -> Result<(), Error> {
            let mut workspace = $workspace::new();
            for b in [1, 8, 17, 168] {
                for valid in 1..=8 {
                    let input = [1; 35];
                    let bits = Fips202BitString::new(&input, valid)
                        .map_err(|_| Error::InvalidBitString)?;
                    let custom =
                        Fips202BitString::new(&[3], 2).map_err(|_| Error::InvalidBitString)?;
                    let plan = crate::$plan::new_bits(bits, b)?;
                    let mut output = [0xa5; 259];
                    let mut expected = [0; 259];
                    let mut storage = [0; 168];
                    let block = storage.get_mut(..b).ok_or(Error::StateConsumed)?;
                    crate::$fixed::new_bits(block, custom)?.finalize_bits(
                        bits,
                        Fips202Output::new(&mut expected, valid)
                            .map_err(|_| Error::InvalidBitString)?,
                    )?;
                    workspace.with_bits(&plan, custom, |mut root| {
                        let mut leaf = [0xa5; $size];
                        for index in 0..plan.leaf_count() {
                            root.merge(plan.job(index)?.execute(&mut leaf)?)?;
                            assert_eq!(leaf, [0; $size]);
                        }
                        root.finalize_public_bits(&mut output, valid, Public::acknowledge())
                    })??;
                    assert_eq!(output, expected);
                    assert!(workspace.cleared());
                    let secret = workspace.with_bits(&plan, custom, |mut root| {
                        let mut leaf = [0; $size];
                        for index in 0..plan.leaf_count() {
                            root.merge(plan.job(index)?.execute(&mut leaf)?)?;
                        }
                        root.finalize_secret_bits(&mut output, valid)
                    })??;
                    assert_eq!(secret.expose(), expected);
                    drop(secret);
                    assert_eq!(output, [0; 259]);
                    crate::$xof::new_bits(block, custom)?
                        .finalize_bits_xof(bits)?
                        .squeeze_final_bits(
                            Fips202Output::new(&mut expected, valid)
                                .map_err(|_| Error::InvalidBitString)?,
                        )?;
                    let (prefix, tail) = output.split_at_mut(169);
                    let secret = workspace.with_bits(&plan, custom, |mut root| {
                        let mut leaf = [0; $size];
                        for index in 0..plan.leaf_count() {
                            root.merge(plan.job(index)?.execute(&mut leaf)?)?;
                        }
                        let mut reader = root.finalize_xof()?;
                        reader.squeeze_public(prefix, Public::acknowledge())?;
                        reader.squeeze_final_bits_secret(tail, valid)
                    })??;
                    assert_eq!(prefix, expected.get(..169).ok_or(Error::StateConsumed)?);
                    assert_eq!(
                        secret.expose(),
                        expected.get(169..).ok_or(Error::StateConsumed)?
                    );
                    drop(secret);
                    assert_eq!(tail, &[0; 90]);
                    assert!(workspace.cleared());
                }
            }
            Ok(())
        }
        #[test]
        fn $lifecycle() -> Result<(), ParallelHashError> {
            let plan = crate::$plan::new(b"first second", 8)?;
            let wrong = crate::$plan::new(b"first second", 8)?;
            let mut workspace = $workspace::new();
            for mode in 0..4 {
                let mut output = [0xa5; 32];
                workspace.with(&plan, b"", |mut root| {
                    let mut leaf = [0xa5; $size];
                    if mode == 0 {
                        assert_eq!(
                            root.merge(wrong.job(0)?.execute(&mut leaf)?),
                            Err(Error::LeafIdentity)
                        );
                    } else if mode == 1 {
                        assert_eq!(
                            root.merge(plan.job(1)?.execute(&mut leaf)?),
                            Err(Error::LeafOrder)
                        );
                    } else if mode == 2 {
                        root.merge(plan.job(0)?.execute(&mut leaf)?)?;
                        assert_eq!(
                            root.merge(plan.job(0)?.execute(&mut leaf)?),
                            Err(Error::LeafOrder)
                        );
                    } else {
                        root.merge(plan.job(0)?.execute(&mut leaf)?)?;
                        assert!(root.finalize_secret(&mut output).is_err());
                        assert_eq!(leaf, [0; $size]);
                        return Ok::<(), Error>(());
                    }
                    assert_eq!(leaf, [0; $size]);
                    assert_eq!(
                        root.merge(plan.job(0)?.execute(&mut leaf)?),
                        Err(Error::StateConsumed)
                    );
                    assert!(root.finalize_secret(&mut output).is_err());
                    Ok(())
                })??;
                assert_eq!(output, [0; 32]);
                assert!(workspace.cleared());
            }
            for mode in 0..3 {
                workspace.with(&plan, b"", |mut root| {
                    let mut leaf = [0; $size];
                    root.merge(plan.job(0)?.execute(&mut leaf)?)?;
                    if mode == 0 {
                        core::mem::forget(root);
                    } else if mode == 1 {
                        root.cancel();
                    } else {
                        root.merge(plan.job(1)?.execute(&mut leaf)?)?;
                        core::mem::forget(root.finalize_xof()?);
                    }
                    Ok::<(), Error>(())
                })??;
                assert!(workspace.cleared());
            }
            let empty = crate::$plan::new(b"", 8)?;
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
            workspace.with(&empty, b"", |root| {
                root.finalize_public(&mut [], Public::acknowledge())
            })??;
            drop(workspace.with(&empty, b"", |root| root.finalize_secret(&mut []))??);
            let mut output = [0xa5; 32];
            workspace.with(&empty, b"", |root| {
                root.finalize_xof()?
                    .squeeze_public(&mut output, Public::acknowledge())
            })??;
            assert_ne!(output, [0xa5; 32]);
            assert!(workspace.cleared());
            Ok(())
        }
    };
}
check!(
    scoped_scheduled128_matches,
    scoped_scheduled128_lifecycle,
    ParallelHash128CollectorWorkspace,
    ParallelHash128Plan,
    ParallelHash128,
    ParallelHashXof128,
    32
);
check!(
    scoped_scheduled256_matches,
    scoped_scheduled256_lifecycle,
    ParallelHash256CollectorWorkspace,
    ParallelHash256Plan,
    ParallelHash256,
    ParallelHashXof256,
    64
);
