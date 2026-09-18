use brynja_crypto_cpu::static_execution::{Authority, Kernel};

#[test]
fn scoped_tuple_requires_exact_compiled_authority() {
    #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
    assert!(Authority::new(Kernel::X86Keccak).is_err());
    #[cfg(not(all(
        target_arch = "aarch64",
        target_feature = "neon",
        target_feature = "sha3"
    )))]
    assert!(Authority::new(Kernel::ArmKeccak).is_err());
}

#[cfg(any(
    all(target_arch = "x86_64", target_feature = "avx2"),
    all(
        target_arch = "aarch64",
        target_feature = "neon",
        target_feature = "sha3"
    )
))]
mod native {
    use super::*;
    use brynja_hash_tuple::{
        Fips202BitString, TupleHashError as Error, TupleHashPublicDeclassification as Public,
        execution::{KeccakSession, in_place as api},
    };
    use std::{
        io,
        panic::{AssertUnwindSafe, catch_unwind},
    };
    fn bad(error: impl core::fmt::Debug) -> io::Error {
        io::Error::other(format!("scoped TupleHash: {error:?}"))
    }
    fn owner() -> Result<Authority, io::Error> {
        Authority::new(if cfg!(target_arch = "aarch64") {
            Kernel::ArmKeccak
        } else {
            Kernel::X86Keccak
        })
        .map_err(bad)
    }
    fn session(owner: &Authority) -> Result<KeccakSession<'_>, io::Error> {
        KeccakSession::from_static(owner).map_err(bad)
    }
    macro_rules! check {
        ($name:ident, $workspace:ident, $ordinary:ident) => {
            #[test]
            fn $name() -> Result<(), io::Error> {
                let authority = owner()?;
                let mut workspace = api::$workspace::new(session(&authority)?).map_err(bad)?;
                assert_eq!(workspace.report(), authority.report());
                let mut expected = [0; 337];
                let mut reference = brynja_hash_tuple::$ordinary::new(b"domain").map_err(bad)?;
                reference
                    .push_item_bits(Fips202BitString::new(&[5], 3).map_err(bad)?)
                    .map_err(bad)?;
                reference.push_item(b"secret message").map_err(bad)?;
                reference.finalize(&mut expected).map_err(bad)?;
                let mut output = [0xa5; 337];
                let secret = workspace
                    .with(b"domain", |mut state| {
                        state.push_item_bits(
                            Fips202BitString::new(&[5], 3).map_err(|_| Error::InvalidBitString)?,
                        )?;
                        let mut item = state.begin_item(112)?;
                        item.update(b"secret ")?;
                        item.update(b"message")?;
                        item.finish()?;
                        state.finalize_secret(&mut output)
                    })
                    .map_err(bad)?
                    .map_err(bad)?;
                assert_eq!(secret.expose(), expected);
                drop(secret);
                assert_eq!(output, [0; 337]);
                let mut scratch = [0xa5; 350];
                workspace
                    .with_scratch(b"domain", &mut scratch, |mut state| {
                        state.push_item_bits(
                            Fips202BitString::new(&[5], 3).map_err(|_| Error::InvalidBitString)?,
                        )?;
                        state.push_item(b"secret message")?;
                        state.finalize_public(&mut output, Public::acknowledge())
                    })
                    .map_err(bad)?
                    .map_err(bad)?;
                assert_eq!(output, expected);
                assert_eq!(scratch, [0; 350]);
                for valid in 1..=8 {
                    let mut expected = [0; 19];
                    let mut reference =
                        brynja_hash_tuple::$ordinary::new(b"partial").map_err(bad)?;
                    reference.push_item(b"x").map_err(bad)?;
                    reference
                        .finalize_bits(
                            brynja_hash_tuple::Fips202Output::new(&mut expected, valid)
                                .map_err(bad)?,
                        )
                        .map_err(bad)?;
                    let mut actual = [0xa5; 19];
                    let secret = workspace
                        .with(b"partial", |mut state| {
                            state.push_item(b"x")?;
                            state.finalize_secret_bits(&mut actual, valid)
                        })
                        .map_err(bad)?
                        .map_err(bad)?;
                    assert_eq!(secret.expose(), expected);
                    drop(secret);
                    assert_eq!(actual, [0; 19]);
                    workspace
                        .with(b"partial", |mut state| {
                            state.push_item(b"x")?;
                            state.finalize_public_bits(&mut actual, valid, Public::acknowledge())
                        })
                        .map_err(bad)?
                        .map_err(bad)?;
                    assert_eq!(actual, expected);
                }
                for width in [0, 1, 168, 336] {
                    let mut scratch = vec![0x55; width];
                    output.fill(0xa5);
                    assert!(
                        workspace
                            .with_scratch(b"", &mut scratch, |state| state
                                .finalize_public(&mut output, Public::acknowledge()))
                            .map_err(bad)?
                            .is_err()
                    );
                    assert_eq!(output, [0xa5; 337]);
                    assert!(scratch.iter().all(|byte| *byte == 0));
                }
                output.fill(0xa5);
                assert!(
                    workspace
                        .with(b"", |state| state
                            .finalize_public(&mut output, Public::acknowledge()))
                        .map_err(bad)?
                        .is_err()
                );
                assert_eq!(output, [0xa5; 337]);
                for valid in [0, 9, 255] {
                    assert!(
                        workspace
                            .with(b"", |state| state.finalize_secret_bits(&mut output, valid))
                            .map_err(bad)?
                            .is_err()
                    );
                    assert_eq!(output, [0; 337]);
                    output.fill(0xa5);
                    assert!(
                        workspace
                            .with(b"", |state| state.finalize_public_bits(
                                &mut output,
                                valid,
                                Public::acknowledge()
                            ))
                            .map_err(bad)?
                            .is_err()
                    );
                    assert_eq!(output, [0xa5; 337]);
                }
                for action in 0..5 {
                    scratch.fill(0x55);
                    workspace
                        .with_scratch(b"", &mut scratch, |mut state| -> Result<(), Error> {
                            let mut item = state.begin_item(8)?;
                            match action {
                                0 => drop(item),
                                1 => item.cancel(),
                                2 => core::mem::forget(item),
                                3 => {
                                    item.update(b"x")?;
                                    core::mem::forget(item);
                                }
                                _ => {
                                    assert!(item.update(b"xx").is_err());
                                    drop(item);
                                }
                            }
                            output.fill(0xa5);
                            assert!(state.finalize_secret(&mut output).is_err());
                            assert_eq!(output, [0; 337]);
                            Ok(())
                        })
                        .map_err(bad)?
                        .map_err(bad)?;
                    assert_eq!(scratch, [0; 350]);
                    // Caller mistakes do not revoke the authority; the next scope works.
                    workspace
                        .with(b"", |state| state.finalize_secret(&mut output).map(drop))
                        .map_err(bad)?
                        .map_err(bad)?;
                }
                for action in 0..3 {
                    scratch.fill(0x55);
                    let outcome = catch_unwind(AssertUnwindSafe(|| {
                        workspace.with_scratch(
                            b"",
                            &mut scratch,
                            |mut state| -> Result<(), Error> {
                                state.push_item(b"secret")?;
                                match action {
                                    0 => state.cancel(),
                                    1 => core::mem::forget(state),
                                    _ => panic!("scope unwind"),
                                }
                                Ok(())
                            },
                        )
                    }));
                    if action == 2 {
                        assert!(outcome.is_err());
                    } else {
                        assert!(matches!(outcome, Ok(Ok(Ok(())))));
                    }
                    assert_eq!(scratch, [0; 350]);
                    workspace
                        .with(b"", |state| state.finalize_secret(&mut output).map(drop))
                        .map_err(bad)?
                        .map_err(bad)?;
                }
                // A revoked session cannot be reused, regardless of empty output.
                workspace
                    .with(b"", |mut state| -> Result<(), Error> {
                        state.push_item(b"secret")?;
                        authority.quarantine();
                        output.fill(0xa5);
                        assert!(state.finalize_secret(&mut output).is_err());
                        assert_eq!(output, [0; 337]);
                        Ok(())
                    })
                    .map_err(bad)?
                    .map_err(bad)?;
                scratch.fill(0xa5);
                output.fill(0xa5);
                let mut called = false;
                assert!(
                    workspace
                        .with_scratch(b"", &mut scratch, |_| {
                            called = true;
                            output.fill(0);
                        })
                        .is_err()
                );
                assert!(!called);
                assert_eq!(scratch, [0; 350]);
                assert_eq!(output, [0xa5; 337]);
                assert!(session(&authority).is_err());
                for width in [0, 32] {
                    for public in [false, true] {
                        let authority = owner()?;
                        let mut workspace =
                            api::$workspace::new(session(&authority)?).map_err(bad)?;
                        let mut destination = vec![0xa5; width];
                        workspace
                            .with(b"", |mut state| -> Result<(), Error> {
                                state.push_item(b"secret")?;
                                authority.quarantine();
                                if public {
                                    assert!(
                                        state
                                            .finalize_public(
                                                &mut destination,
                                                Public::acknowledge()
                                            )
                                            .is_err()
                                    );
                                    assert!(destination.iter().all(|byte| *byte == 0xa5));
                                } else {
                                    assert!(state.finalize_secret(&mut destination).is_err());
                                    assert!(destination.iter().all(|byte| *byte == 0));
                                }
                                Ok(())
                            })
                            .map_err(bad)?
                            .map_err(bad)?;
                    }
                }
                // Revocation also preserves public output and terminates open writers.
                for public in [false, true] {
                    let authority = owner()?;
                    let mut workspace = api::$workspace::new(session(&authority)?).map_err(bad)?;
                    workspace
                        .with(b"", |mut state| -> Result<(), Error> {
                            let mut item = state.begin_item(16)?;
                            item.update(b"x")?;
                            authority.quarantine();
                            assert!(item.update(b"y").is_err());
                            assert!(item.finish().is_err());
                            output.fill(0xa5);
                            if public {
                                assert!(
                                    state
                                        .finalize_public(&mut output, Public::acknowledge())
                                        .is_err()
                                );
                                assert_eq!(output, [0xa5; 337]);
                            } else {
                                assert!(state.finalize_secret(&mut output).is_err());
                                assert_eq!(output, [0; 337]);
                            }
                            Ok(())
                        })
                        .map_err(bad)?
                        .map_err(bad)?;
                }
                Ok(())
            }
        };
    }
    check!(
        scoped_accelerated_tuple128_lifecycle,
        TupleHash128Workspace,
        TupleHash128
    );
    check!(
        scoped_accelerated_tuple256_lifecycle,
        TupleHash256Workspace,
        TupleHash256
    );
}
