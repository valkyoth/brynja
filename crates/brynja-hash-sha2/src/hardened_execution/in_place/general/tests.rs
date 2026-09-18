extern crate std;
use super::super::tests::{authority, cleared, execution};
use super::*;

fn parameter(t: u16) -> Result<Sha512TBits, Error> {
    Sha512TBits::new(t).map_err(|_| Error::Failed)
}
fn declassify() -> PublicDeclassification {
    PublicDeclassification::acknowledge()
}

#[test]
fn scoped_general_execution_all_parameters_and_boundaries() -> Result<(), Error> {
    let cpu = authority(true);
    for owner in [None, cpu.as_ref()] {
        for t in (1..512).filter(|t| *t != 384) {
            let p = parameter(t)?;
            let mut workspace = Sha512TWorkspace::new(p, execution(owner)?)?;
            assert_eq!(workspace.parameter(), p);
            let address = core::ptr::from_ref(&workspace.engine);
            for length in [0, 1, 111, 112, 127, 128, 129, 256] {
                let input = std::vec![0xa6; length];
                let expected = crate::sha512_t(p, &input).map_err(|_| Error::Failed)?;
                let mut output = std::vec![0xa5; p.output_bytes()];
                let secret = workspace.with(|mut state| {
                    assert_eq!(core::ptr::from_ref(&*state.engine), address);
                    assert_eq!(state.parameter(), p);
                    for part in input.chunks(19) {
                        state.update(&[])?;
                        state.update(part)?;
                    }
                    state.finalize_secret(&mut output)
                })??;
                assert!(cleared(&workspace.engine.owner));
                assert_eq!(secret.digest.parameter(), p);
                assert_eq!(secret.digest.as_bytes(), expected.as_bytes());
                assert_eq!(secret.report.route, workspace.route());
                assert_eq!(secret.report.message_blocks, (length / 128) as u128);
                assert_eq!(
                    secret.report.padding_blocks,
                    if length % 128 < 112 { 1 } else { 2 }
                );
                assert_eq!(secret.report.portable_iv_blocks, 1);
                drop(secret);
                assert!(output.iter().all(|b| *b == 0));
                let public = workspace.with(|mut state| {
                    state.update(&input)?;
                    state.finalize_public(declassify())
                })??;
                assert_eq!(public.digest, expected);
                assert_eq!(public.report.portable_iv_blocks, 1);
                for valid in 1..=8 {
                    let mut full = input.clone();
                    full.push(0x80);
                    let bits = BitString::new(&full, valid).map_err(|_| Error::Failed)?;
                    let expected = crate::sha512_t_bits(p, bits).map_err(|_| Error::Failed)?;
                    let secret = workspace.with(|mut state| {
                        state.update(&input)?;
                        state.finalize_bits_secret(
                            BitString::new(&[0x80], valid).map_err(|_| Error::Failed)?,
                            &mut output,
                        )
                    })??;
                    assert_eq!(secret.digest.as_bytes(), expected.as_bytes());
                    assert_eq!(secret.digest.parameter(), p);
                    drop(secret);
                    assert!(output.iter().all(|b| *b == 0));
                    assert_eq!(
                        workspace
                            .with(|state| state.finalize_bits_public(bits, declassify()))??
                            .digest,
                        expected
                    );
                    assert!(cleared(&workspace.engine.owner));
                }
            }
        }
    }
    Ok(())
}

#[test]
fn scoped_general_execution_cleanup_terminal_errors_and_unwind() -> Result<(), Error> {
    for t in [1, 9, 224, 256, 511] {
        let p = parameter(t)?;
        let mut workspace = Sha512TWorkspace::new(p, Execution::portable())?;
        for mode in 0..5 {
            workspace.with(|mut state| {
                state.update(b"secret")?;
                match mode {
                    0 => state.cancel(),
                    1 => drop(state),
                    2 => core::mem::forget(state),
                    _ => {
                        if mode == 3 {
                            state.engine.owner.message_length.fill(0xff);
                        } else {
                            state.engine.report.message_blocks = u128::MAX;
                        }
                        assert_eq!(state.update(&[0; 128]), Err(Error::MessageTooLong));
                        assert!(cleared(&state.engine.owner));
                        assert_eq!(state.update(&[]), Err(Error::Failed));
                        core::mem::forget(state);
                    }
                }
                Ok::<(), Error>(())
            })??;
            assert!(cleared(&workspace.engine.owner));
        }
        for width in 0..=65 {
            if width == p.output_bytes() {
                continue;
            }
            let mut output = std::vec![0xa5; width];
            let result = workspace.with(|mut state| {
                state.update(b"secret")?;
                state.finalize_secret(&mut output)
            })?;
            assert!(matches!(result, Err(Error::OutputLength)));
            drop(result);
            assert!(output.iter().all(|b| *b == 0));
            assert!(cleared(&workspace.engine.owner));
        }
        for tail in [false, true] {
            let final_bits = BitString::new(&[0x80], 1).map_err(|_| Error::Failed)?;
            let mut output = std::vec![0xa5; p.output_bytes()];
            workspace.with(|mut state| {
                state.engine.owner.message_length.fill(0xff);
                assert!(state.update(b"x").is_err());
                let result = if tail {
                    state.finalize_bits_secret(final_bits, &mut output)
                } else {
                    state.finalize_secret(&mut output)
                };
                assert!(matches!(result, Err(Error::Failed)));
            })?;
            assert!(output.iter().all(|b| *b == 0));
            assert!(cleared(&workspace.engine.owner));
            workspace.with(|mut state| {
                state.engine.owner.message_length.fill(0xff);
                assert!(state.update(b"x").is_err());
                let result = if tail {
                    state.finalize_bits_public(final_bits, declassify())
                } else {
                    state.finalize_public(declassify())
                };
                assert!(matches!(result, Err(Error::Failed)));
            })?;
        }
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = workspace.with(|mut state| {
                assert!(state.update(b"secret").is_ok());
                core::mem::forget(state);
                std::panic::resume_unwind(std::boxed::Box::new(()));
            });
        }));
        assert!(caught.is_err());
        assert!(cleared(&workspace.engine.owner));
        workspace.engine.restart()?;
        initialize64(&mut workspace.engine, p.initial_words());
        let mut state = Sha512T {
            engine: &mut workspace.engine,
            parameter: p,
        };
        state.update(b"secret")?;
        state.cancel();
        assert!(cleared(&workspace.engine.owner));
        assert_eq!(
            workspace
                .with(|mut state| {
                    state.update(b"abc")?;
                    state.finalize_public(declassify())
                })??
                .digest,
            crate::sha512_t(p, b"abc").map_err(|_| Error::Failed)?
        );
    }
    Ok(())
}

#[test]
fn scoped_general_execution_revocation_and_wrong_family() -> Result<(), Error> {
    if let Some(narrow) = authority(false) {
        assert!(matches!(
            Sha512TWorkspace::new(parameter(9)?, execution(Some(&narrow))?),
            Err(Error::Backend(_))
        ));
    }
    let Some(owner) = authority(true) else {
        return Ok(());
    };
    let mut workspace = Sha512TWorkspace::new(parameter(9)?, execution(Some(&owner))?)?;
    let mut output = [0xa5; 2];
    workspace.with(|mut state| {
        state.update(b"secret")?;
        owner.quarantine();
        assert!(matches!(state.update(&[]), Err(Error::Backend(_))));
        assert!(cleared(&state.engine.owner));
        assert!(matches!(
            state.finalize_secret(&mut output),
            Err(Error::Failed)
        ));
        Ok::<(), Error>(())
    })??;
    assert_eq!(output, [0; 2]);
    let mut called = false;
    assert!(matches!(
        workspace.with(|_| called = true),
        Err(Error::Backend(_))
    ));
    assert!(!called);
    assert!(cleared(&workspace.engine.owner));
    Ok(())
}
