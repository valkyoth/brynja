use super::{Fips202BitString, KmacError, api, bad, owner, session};
use brynja_mac_kmac::{KmacPublicDeclassification, KmacServiceStatus};
use std::io;
fn public() -> KmacPublicDeclassification {
    KmacPublicDeclassification::acknowledge()
}

macro_rules! lifecycle {
    ($workspace:ident, $reference:ident) => {{
        let authority = owner()?;
        let mut workspace = api::$workspace::new(session(&authority)?).map_err(bad)?;
        let key = [0x42; 32];
        let mut expected = [0; 337];
        let reference =
            brynja_mac_kmac::$reference(&key, b"message", b"domain", &mut expected).map_err(bad)?;
        let mut output = [0xa5; 337];
        let secret = workspace
            .with(&key, b"domain", |mut state| {
                assert_eq!(state.service_status(), KmacServiceStatus::NonApproved);
                state.update(b"message")?;
                let mut reader = state.finalize_xof()?;
                assert_eq!(reader.service_status(), KmacServiceStatus::NonApproved);
                reader.squeeze_secret(&mut output)
            })
            .map_err(bad)?
            .map_err(bad)?;
        assert_eq!(secret.expose(), reference.expose());
        drop(secret);
        assert_eq!(output, [0; 337]);
        let mut scratch = [0x5a; 400];
        workspace
            .with_scratch(&key, b"domain", &mut scratch, |mut state| {
                state.update(b"message")?;
                state.finalize_xof()?.squeeze_public(&mut output, public())
            })
            .map_err(bad)?
            .map_err(bad)?;
        assert_eq!(output, reference.expose());
        assert_eq!(scratch, [0; 400]);
        for width in [0, 1, 168, 336] {
            let mut staging = vec![0x5a; width];
            output.fill(0xa5);
            workspace
                .with_scratch(&key, b"domain", &mut staging, |state| {
                    let mut reader = state.finalize_xof()?;
                    assert!(reader.squeeze_public(&mut output, public()).is_err());
                    assert_eq!(output, [0xa5; 337]);
                    assert_eq!(
                        reader.squeeze_public(&mut [], public()),
                        Err(KmacError::StateConsumed)
                    );
                    assert!(matches!(
                        reader.squeeze_secret(&mut output),
                        Err(KmacError::StateConsumed)
                    ));
                    Ok::<(), KmacError>(())
                })
                .map_err(bad)?
                .map_err(bad)?;
            assert_eq!(output, [0; 337]);
            assert!(staging.iter().all(|b| *b == 0));
        }
        output.fill(0xa5);
        workspace
            .with(&key, b"", |state| {
                let mut reader = state.finalize_xof()?;
                assert!(reader.squeeze_public(&mut output, public()).is_err());
                assert_eq!(output, [0xa5; 337]);
                assert!(matches!(
                    reader.squeeze_final_bits_secret(&mut output, 5),
                    Err(KmacError::StateConsumed)
                ));
                Ok::<(), KmacError>(())
            })
            .map_err(bad)?
            .map_err(bad)?;
        assert_eq!(output, [0; 337]);
        for valid in [0, 9, 255] {
            output.fill(0xa5);
            assert!(
                workspace
                    .with(&key, b"", |state| state
                        .finalize_xof()?
                        .squeeze_final_bits_secret(&mut output, valid))
                    .map_err(bad)?
                    .is_err()
            );
            assert_eq!(output, [0; 337]);
            output.fill(0xa5);
            scratch.fill(0x5a);
            assert!(
                workspace
                    .with_scratch(&key, b"", &mut scratch, |state| state
                        .finalize_xof()?
                        .squeeze_final_bits_public(&mut output, valid, public()))
                    .map_err(bad)?
                    .is_err()
            );
            assert_eq!(output, [0xa5; 337]);
            assert_eq!(scratch, [0; 400]);
        }
        workspace
            .with(&key, b"", |state| {
                state
                    .finalize_xof()?
                    .squeeze_final_bits_public(&mut [], 0, public())
            })
            .map_err(bad)?
            .map_err(bad)?;
        drop(
            workspace
                .with(&key, b"", |state| {
                    state.finalize_xof()?.squeeze_final_bits_secret(&mut [], 0)
                })
                .map_err(bad)?
                .map_err(bad)?,
        );
        let mut called = false;
        scratch.fill(0x5a);
        assert!(matches!(
            workspace.with_scratch(&[], b"", &mut scratch, |_| called = true),
            Err(KmacError::KeyTooShort)
        ));
        assert!(!called);
        assert_eq!(scratch, [0; 400]);
        assert!(matches!(
            workspace.with_conformance(&[1], b"", |state| state.finalize_xof().map(|_| ())),
            Ok(Err(KmacError::KeyTooShort))
        ));
        for mode in 0..3 {
            workspace
                .with(&key, b"domain", |mut state| {
                    state.update(b"secret")?;
                    let reader = state.finalize_xof()?;
                    match mode {
                        0 => reader.cancel(),
                        1 => drop(reader),
                        _ => core::mem::forget(reader),
                    };
                    Ok::<(), KmacError>(())
                })
                .map_err(bad)?
                .map_err(bad)?;
            let secret = workspace
                .with(&key, b"domain", |mut state| {
                    state.update(b"message")?;
                    state.finalize_xof()?.squeeze_secret(&mut output)
                })
                .map_err(bad)?
                .map_err(bad)?;
            assert_eq!(secret.expose(), reference.expose());
            drop(secret);
        }
        scratch.fill(0x5a);
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = workspace.with_scratch(&key, b"domain", &mut scratch, |state| {
                if let Ok(reader) = state.finalize_xof() {
                    core::mem::forget(reader);
                    std::panic::resume_unwind(Box::new(()));
                }
            });
        }));
        assert!(caught.is_err());
        assert_eq!(scratch, [0; 400]);
        let tail = Fips202BitString::new(b"message", 8).map_err(bad)?;
        let secret = workspace
            .with(&key, b"domain", |state| {
                state
                    .finalize_bits_xof(tail)?
                    .squeeze_final_bits_secret(&mut output, 5)
            })
            .map_err(bad)?
            .map_err(bad)?;
        let mut masked = reference.expose().to_vec();
        if let Some(last) = masked.last_mut() {
            *last &= 0x1f;
        }
        assert_eq!(secret.expose(), masked);
        drop(secret);
        assert_eq!(output, [0; 337]);
    }};
}

#[test]
fn scoped_native_xof_output_and_lifecycle() -> Result<(), io::Error> {
    lifecycle!(KmacXof128Workspace, kmacxof128_secret);
    lifecycle!(KmacXof256Workspace, kmacxof256_secret);
    Ok(())
}

macro_rules! revoked {
    ($workspace:ident) => {{
        for mode in 0..4 {
            let authority = owner()?;
            let mut workspace = api::$workspace::new(session(&authority)?).map_err(bad)?;
            let mut output = [0xa5; 32];
            workspace
                .with(&[0; 32], b"", |state| {
                    let mut reader = state.finalize_xof()?;
                    authority.quarantine();
                    if mode == 3 {
                        assert!(reader.squeeze_final_bits_secret(&mut output, 5).is_err());
                    } else {
                        match mode {
                            0 => {
                                assert!(reader.squeeze_public(&mut output, public()).is_err());
                                assert_eq!(output, [0xa5; 32]);
                            }
                            1 => {
                                assert!(reader.squeeze_secret(&mut output).is_err());
                                assert_eq!(output, [0; 32]);
                            }
                            _ => assert!(reader.squeeze_public(&mut [], public()).is_err()),
                        }
                        assert!(matches!(
                            reader.squeeze_secret(&mut output),
                            Err(KmacError::StateConsumed)
                        ));
                        assert_eq!(
                            reader.squeeze_public(&mut [], public()),
                            Err(KmacError::StateConsumed)
                        );
                    }
                    Ok::<(), KmacError>(())
                })
                .map_err(bad)?
                .map_err(bad)?;
            assert_eq!(output, [0; 32]);
            let mut called = false;
            assert!(workspace.with(&[0; 32], b"", |_| called = true).is_err());
            assert!(!called);
            assert!(session(&authority).is_err());
        }
    }};
}
#[test]
fn scoped_xof_revocation_is_terminal() -> Result<(), io::Error> {
    revoked!(KmacXof128Workspace);
    revoked!(KmacXof256Workspace);
    Ok(())
}
