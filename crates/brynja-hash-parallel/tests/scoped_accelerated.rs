//! Scoped accelerated fixed-output correctness, staging and authority lifecycle.
#![cfg(feature = "hardened-execution")]
use brynja_crypto_cpu::static_execution::{Authority, Error as CpuError, Health, Kernel};
use brynja_hash_parallel::{
    self as hash, Fips202BitString, Fips202Output, ParallelHashError as Error,
    ParallelHashPublicDeclassification as Public,
    execution::{KeccakSession, in_place as api},
};
use std::panic::{AssertUnwindSafe, catch_unwind};

fn owner() -> Result<Option<Authority>, Box<dyn std::error::Error>> {
    let kernel = if cfg!(target_arch = "aarch64") {
        Kernel::ArmKeccak
    } else {
        Kernel::X86Keccak
    };
    match Authority::new(kernel) {
        Ok(owner) => Ok(Some(owner)),
        Err(CpuError::MissingTargetFeatures | CpuError::WrongArchitecture)
            if std::env::var_os("BRYNJA_REQUIRE_SCOPED_PARALLEL").is_none() =>
        {
            Ok(None)
        }
        Err(error) => Err(format!("required scoped ParallelHash route: {error:?}").into()),
    }
}
fn session(owner: &Authority) -> Result<KeccakSession<'_>, Error> {
    KeccakSession::from_static(owner)
        .map_err(|e| Error::Execution(brynja_hash_sha3::hardened_execution::Error::Backend(e)))
}

macro_rules! check {
    ($test:ident, $lifecycle:ident, $workspace:ident, $ordinary:ident) => {
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
                assert_eq!(workspace.root_report().kernel, root.report().kernel);
                assert_eq!(workspace.leaf_report().kernel, leaf.report().kernel);
                for b in [1, 8, 17, 168] {
                    for valid in 1..=8 {
                        let input = [0x35; 173];
                        let tail = Fips202BitString::new(&[1], valid)
                            .map_err(|_| Error::InvalidBitString)?;
                        let custom =
                            Fips202BitString::new(&[3], 2).map_err(|_| Error::InvalidBitString)?;
                        let mut storage = [0xa5; 168];
                        let block = storage.get_mut(..b).ok_or(Error::StateConsumed)?;
                        let mut reference_storage = [0; 168];
                        let mut reference = hash::$ordinary::new_bits(
                            reference_storage.get_mut(..b).ok_or(Error::StateConsumed)?,
                            custom,
                        )?;
                        reference.update(&input)?;
                        let mut expected = [0; 259];
                        reference.finalize_bits(
                            tail,
                            Fips202Output::new(&mut expected, valid)
                                .map_err(|_| Error::InvalidBitString)?,
                        )?;
                        let mut scratch = [0xa5; 300];
                        let mut output = [0xa5; 259];
                        workspace.with_bits_and_scratch(
                            block,
                            custom,
                            &mut scratch,
                            |mut state| {
                                for chunk in input.chunks(13) {
                                    state.update(chunk)?;
                                }
                                state.finalize_bits_public(
                                    tail,
                                    &mut output,
                                    valid,
                                    Public::acknowledge(),
                                )
                            },
                        )??;
                        assert_eq!(output, expected);
                        assert_eq!(scratch, [0; 300]);
                        assert!(block.iter().all(|b| *b == 0));
                        let secret = workspace.with_bits(block, custom, |mut state| {
                            state.update(&input)?;
                            state.finalize_bits_secret(tail, &mut output, valid)
                        })??;
                        assert_eq!(secret.expose(), expected);
                        drop(secret);
                        assert_eq!(output, [0; 259]);
                    }
                }
                let mut block = [0; 8];
                let mut scratch = [0xa5; 64];
                let mut entered = false;
                assert!(
                    workspace
                        .with_scratch(&mut [], b"", &mut scratch, |_| entered = true)
                        .is_err()
                );
                assert!(!entered);
                assert_eq!(scratch, [0; 64]);
                let mut output = [0xa5; 169];
                assert!(
                    workspace
                        .with(&mut block, b"", |state| state
                            .finalize_public(&mut output, Public::acknowledge()))?
                        .is_err()
                );
                assert_eq!(output, [0xa5; 169]);
                for valid in [0, 9, 255] {
                    assert!(
                        workspace
                            .with(&mut block, b"", |state| state.finalize_public_bits(
                                &mut output[..3],
                                valid,
                                Public::acknowledge()
                            ))?
                            .is_err()
                    );
                    assert_eq!(output, [0xa5; 169]);
                    let mut secret_output = [0xa5; 3];
                    assert!(
                        workspace
                            .with(&mut block, b"", |state| state
                                .finalize_secret_bits(&mut secret_output, valid))?
                            .is_err()
                    );
                    assert_eq!(secret_output, [0; 3]);
                }
                for action in 0..3 {
                    let mut scratch = [0xa5; 300];
                    let result = catch_unwind(AssertUnwindSafe(|| {
                        workspace.with_scratch(&mut block, b"", &mut scratch, |mut state| {
                            state.update(b"secret pending")?;
                            match action {
                                0 => state.cancel(),
                                1 => core::mem::forget(state),
                                _ => panic!("injected scope unwind"),
                            }
                            Ok::<(), Error>(())
                        })
                    }));
                    if action == 2 {
                        assert!(result.is_err());
                    } else {
                        assert!(matches!(result, Ok(Ok(Ok(())))));
                    }
                    assert_eq!(block, [0; 8]);
                    assert_eq!(scratch, [0; 300]);
                }
                assert_eq!(workspace.root_report().health, Health::Healthy);
                assert_eq!(workspace.leaf_report().health, Health::Healthy);
                let mut expected = [0; 32];
                hash::$ordinary::new(&mut [0; 8], b"")?.finalize(&mut expected)?;
                workspace.with(&mut block, b"", |state| {
                    state.finalize_public(&mut output[..32], Public::acknowledge())
                })??;
                assert_eq!(&output[..32], &expected);
                let mut same_owner = api::$workspace::new(session(&root)?, session(&root)?)?;
                same_owner.with(&mut block, b"", |state| {
                    state.finalize_public(&mut output[..32], Public::acknowledge())
                })??;
                assert_eq!(&output[..32], &expected);
                Ok(())
            };
            run().map_err(|e| format!("accelerated ParallelHash: {e:?}"))?;
            println!("SCOPED_PARALLELHASH_FIXED: {}", stringify!($workspace));
            Ok(())
        }
        #[test]
        fn $lifecycle() -> Result<(), Box<dyn std::error::Error>> {
            for revoke_root in [false, true] {
                for phase in 0..5 {
                    let Some(root) = owner()? else {
                        return Ok(());
                    };
                    let Some(leaf) = owner()? else {
                        return Ok(());
                    };
                    let run = || -> Result<(), Error> {
                        let mut workspace = api::$workspace::new(session(&root)?, session(&leaf)?)?;
                        let revoke = || {
                            if revoke_root {
                                root.quarantine();
                            } else {
                                leaf.quarantine();
                            }
                        };
                        let mut block = [0xa5; 8];
                        let mut scratch = [0xa5; 64];
                        let mut output = [0xa5; 32];
                        if phase == 0 {
                            revoke();
                        }
                        let mut entered = false;
                        let result =
                            workspace.with_scratch(&mut block, b"", &mut scratch, |mut state| {
                                entered = true;
                                state.update(b"prefix")?;
                                revoke();
                                if phase == 1 || phase == 2 {
                                    assert!(
                                        state
                                            .update(if phase == 1 { b"" } else { b"tail" })
                                            .is_err()
                                    );
                                    assert!(state.update(b"").is_err());
                                    assert!(state.finalize_secret(&mut output).is_err());
                                    assert_eq!(output, [0; 32]);
                                } else if phase == 3 {
                                    assert!(
                                        state
                                            .finalize_public(&mut output, Public::acknowledge())
                                            .is_err()
                                    );
                                    assert_eq!(output, [0xa5; 32]);
                                } else {
                                    assert!(state.finalize_secret(&mut output).is_err());
                                    assert_eq!(output, [0; 32]);
                                }
                                Ok::<(), Error>(())
                            });
                        if phase == 0 {
                            assert!(result.is_err());
                            assert!(!entered);
                            assert_eq!(output, [0xa5; 32]);
                        } else {
                            result??;
                            assert!(entered);
                        }
                        assert_eq!(block, [0; 8]);
                        assert_eq!(scratch, [0; 64]);
                        assert!(workspace.with(&mut block, b"", |_| ()).is_err());
                        Ok(())
                    };
                    run().map_err(|e| format!("scoped revocation: {e:?}"))?;
                }
            }
            Ok(())
        }
    };
}
check!(
    scoped_accelerated_parallel128_matches_and_clears,
    scoped_accelerated_parallel128_revokes,
    ParallelHash128Workspace,
    ParallelHash128
);
check!(
    scoped_accelerated_parallel256_matches_and_clears,
    scoped_accelerated_parallel256_revokes,
    ParallelHash256Workspace,
    ParallelHash256
);
