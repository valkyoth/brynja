use super::*;

macro_rules! scope {
    ($workspace:ident, shake, $operation:expr) => {
        $workspace.with($operation)
    };
    ($workspace:ident, custom, $operation:expr) => {
        $workspace.with(b"secret name", b"secret customization", $operation)
    };
}
macro_rules! lifecycle {
    ($workspace:ident, $state:ident, $kind:ident, $owner:ident) => {{
        let mut workspace = $workspace::new(session(&$owner)?)?;
        for mode in 0..6 {
            scope!(workspace, $kind, |mut state| {
                state.update(b"secret")?;
                state.inner.storage.inner.stage.0.fill(0xa5);
                match mode {
                    0 => state.cancel(), 1 => ::core::mem::forget(state),
                    2 => {
                        state.inner.storage.inner.engine.overflow_message_for_test();
                        assert_eq!(state.update(b"x"), Err(Error::LengthOverflow));
                        assert!(state.inner.storage.cleared_for_test());
                        assert_eq!(state.update(&[]), Err(Error::Terminal));
                        ::core::mem::forget(state);
                    }
                    _ => {
                        let mut reader = state.finalize_xof()?;
                        assert!(reader.inner.storage.inner.stage.0.iter().all(|b| *b == 0));
                        reader.inner.storage.inner.stage.0.fill(0xa5);
                        if mode == 3 { reader.cancel(); }
                        else if mode == 4 { ::core::mem::forget(reader); }
                        else { drop(reader.squeeze_secret(&mut [0; 1])?); }
                    }
                }
                Ok::<(), Error>(())
            })??;
            assert!(workspace.storage.cleared_for_test());
        }
        for reader_phase in [false, true] {
            let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = scope!(workspace, $kind, |mut state| {
                    assert!(state.update(b"secret").is_ok());
                    if reader_phase {
                        if let Ok(mut reader) = state.finalize_xof() {
                            assert!(reader.squeeze_secret(&mut [0; 1]).is_ok());
                            reader.inner.storage.inner.stage.0.fill(0xa5);
                            ::core::mem::forget(reader);
                        }
                    } else { ::core::mem::forget(state); }
                    std::panic::resume_unwind(std::boxed::Box::new(()));
                });
            }));
            assert!(caught.is_err()); assert!(workspace.storage.cleared_for_test());
        }
        // Test the inner destructor independently of the outer scope guard.
        workspace.storage.restart()?;
        let mut state = $state { inner: Borrowed { storage: &mut workspace.storage } };
        state.update(b"secret")?;
        let reader = state.finalize_xof()?;
        reader.inner.storage.inner.stage.0.fill(0xa5);
        drop(reader); assert!(workspace.storage.cleared_for_test());
        for mode in 0..4 {
            for secret in [false, true] {
                let mut output = [0xa5; 600]; let mut scratch = [0x9b; 601];
                scope!(workspace, $kind, |mut state| {
                    state.update(b"secret")?;
                    let mut reader = state.finalize_xof()?;
                    if mode == 0 { reader.inner.storage.inner.engine.remaining_permutations = Some(1); }
                    if mode == 1 { reader.inner.storage.inner.engine.overflow_output_for_test(); }
                    if mode == 2 { reader.inner.storage.clear(); }
                    if mode == 3 {
                        assert_eq!(reader.squeeze_public(&mut [0xa5; 169], public()), Err(Error::OutputLength));
                    }
                    if secret { assert!(reader.squeeze_secret(&mut output).is_err()); }
                    else { assert!(reader.squeeze_public_with_scratch(&mut output, &mut scratch, public()).is_err()); }
                    assert!(reader.inner.storage.cleared_for_test());
                    assert!(matches!(reader.squeeze_secret(&mut []), Err(Error::Terminal)));
                    assert_eq!(reader.squeeze_public(&mut [], public()), Err(Error::Terminal));
                    let mut rejected = [0xa5; 3];
                    assert!(matches!(reader.squeeze_secret(&mut rejected), Err(Error::Terminal)));
                    assert_eq!(rejected, [0; 3]);
                    Ok::<(), Error>(())
                })??;
                assert_eq!(output, [if secret { 0 } else { 0xa5 }; 600]);
                assert_eq!(scratch, [if secret { 0x9b } else { 0 }; 601]);
                assert!(workspace.storage.cleared_for_test());
                workspace.storage.inner.engine.remaining_permutations = None;
            }
        }
        scope!(workspace, $kind, |state| {
            let mut reader = state.finalize_xof()?;
            let mut output = [0xa5; 170]; let mut scratch = [0x9b; 169];
            assert_eq!(reader.squeeze_public_with_scratch(&mut output, &mut scratch, public()), Err(Error::OutputLength));
            assert_eq!(output, [0xa5; 170]); assert_eq!(scratch, [0; 169]);
            assert!(reader.inner.storage.cleared_for_test());
            Ok::<(), Error>(())
        })??;
        for width in [0, 1, 169] {
            for valid in [0, 1, 8, 9, 255] {
                let good = (width == 0 && valid == 0) || (width != 0 && (1..=8).contains(&valid));
                let mut output = std::vec![0xa5; width];
                let result = scope!(workspace, $kind, |state| state.finalize_xof()?.squeeze_final_bits_secret(&mut output, valid))?;
                assert_eq!(result.is_ok(), good); drop(result);
                assert!(output.iter().all(|b| *b == 0)); assert!(workspace.storage.cleared_for_test());
            }
        }
        let mut output = [0xa5; 20];
        drop(scope!(workspace, $kind, |state| state.finalize_xof()?.squeeze_secret(&mut output))??);
        assert_eq!(output, [0; 20]);
    }};
}

#[test]
fn all_scoped_xof_lifecycle_failures_clear_and_terminate() -> Result<(), Error> {
    let Some(owner) = authority()? else {
        return Ok(());
    };
    lifecycle!(Shake128Workspace, Shake128, shake, owner);
    lifecycle!(Shake256Workspace, Shake256, shake, owner);
    lifecycle!(Cshake128Workspace, Cshake128, custom, owner);
    lifecycle!(Cshake256Workspace, Cshake256, custom, owner);
    Ok(())
}

#[test]
fn prefix_failure_and_revocation_skip_callbacks_and_clear() -> Result<(), Error> {
    let Some(owner) = authority()? else {
        return Ok(());
    };
    let mut workspace = Cshake128Workspace::new(session(&owner)?)?;
    workspace.storage.inner.engine.remaining_permutations = Some(0);
    let mut called = false;
    assert_eq!(
        workspace.with(b"secret", b"custom", |_| called = true),
        Err(Error::Terminal)
    );
    assert!(!called);
    assert!(workspace.storage.cleared_for_test());
    workspace.storage.inner.engine.remaining_permutations = None;
    workspace.with(b"secret", b"custom", |mut state| {
        state.update(b"message")?;
        let mut reader = state.finalize_xof()?;
        owner.quarantine();
        let mut output = [0xa5; 20];
        assert!(matches!(
            reader.squeeze_secret(&mut output),
            Err(Error::Backend(_))
        ));
        assert_eq!(output, [0; 20]);
        assert!(reader.inner.storage.cleared_for_test());
        Ok::<(), Error>(())
    })??;
    assert!(matches!(
        workspace.with(b"", b"", |_| called = true),
        Err(Error::Backend(_))
    ));
    assert!(!called);
    assert!(workspace.storage.cleared_for_test());
    Ok(())
}
