use super::*;
extern crate std;

#[test]
fn scoped_xof_returned_secret_matches_known_api() -> Result<(), KmacError> {
    let mut workspace = KmacXof128Workspace::new();
    let key = [0x42; 16];
    let mut expected = [0; 32];
    crate::kmacxof128_public(
        &key,
        b"message",
        b"custom",
        &mut expected,
        KmacPublicDeclassification::acknowledge(),
    )?;
    let mut output = [0xa5; 32];
    let secret = workspace.with(&key, b"custom", |mut state| {
        state.update(b"message")?;
        state.finalize_xof()?.squeeze_secret(&mut output)
    })??;
    assert_eq!(secret.expose(), expected);
    drop(secret);
    assert_eq!(output, [0; 32]);
    assert!(workspace.metadata_cleared());
    Ok(())
}

#[test]
fn scoped_xof_lifecycle_shapes_and_large_public_reads() -> Result<(), KmacError> {
    macro_rules! check {
        ($workspace:ident, $reference:ident) => {{
            let mut workspace = $workspace::new();
            let key = [0x42; 32];
            let mut called = false;
            assert!(matches!(
                workspace.with(&[], b"", |_| called = true),
                Err(KmacError::KeyTooShort)
            ));
            assert!(!called);
            for forget in [false, true] {
                for unwind in [false, true] {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        workspace.with(&key, b"", |mut state| {
                            state.update(b"secret")?;
                            let reader = state.finalize_xof()?;
                            if forget {
                                core::mem::forget(reader);
                            } else {
                                reader.cancel();
                            }
                            if unwind {
                                std::panic::resume_unwind(std::boxed::Box::new(()));
                            }
                            Ok::<(), KmacError>(())
                        })
                    }));
                    if unwind {
                        assert!(result.is_err());
                    } else {
                        assert!(matches!(result, Ok(Ok(Ok(())))));
                    }
                    assert!(workspace.metadata_cleared());
                }
            }
            workspace.with(&key, b"", |state| {
                let mut reader = state.finalize_xof()?;
                let mut output = [0xa5; 169];
                reader.squeeze_public(&mut output, KmacPublicDeclassification::acknowledge())?;
                let mut expected = [0; 169];
                crate::$reference::new(&key, b"")?
                    .finalize_xof()?
                    .squeeze_public(&mut expected, KmacPublicDeclassification::acknowledge())?;
                assert_eq!(output, expected);
                Ok::<(), KmacError>(())
            })??;
            assert!(workspace.metadata_cleared());
            for valid in [0, 9, 255] {
                let mut output = [0xa5; 17];
                assert!(matches!(
                    workspace.with(&key, b"", |state| state
                        .finalize_xof()?
                        .squeeze_final_bits_secret(&mut output, valid))?,
                    Err(KmacError::InvalidBitString)
                ));
                assert_eq!(output, [0; 17]);
                output.fill(0xa5);
                assert!(matches!(
                    workspace.with(&key, b"", |state| state
                        .finalize_xof()?
                        .squeeze_final_bits_public(
                            &mut output,
                            valid,
                            KmacPublicDeclassification::acknowledge()
                        ))?,
                    Err(KmacError::InvalidBitString)
                ));
                assert_eq!(output, [0xa5; 17]);
                assert!(workspace.metadata_cleared());
            }
        }};
    }
    check!(KmacXof128Workspace, KmacXof128);
    check!(KmacXof256Workspace, KmacXof256);
    Ok(())
}

#[cfg(feature = "conformance-testing")]
#[test]
fn scoped_xof_all_tails_streaming_and_mixed_reads() -> Result<(), KmacError> {
    macro_rules! check { ($workspace:ident,$reference:ident) => {{
        let mut workspace=$workspace::new();
        for length in [0usize,1,135,136,167,168,169,337] {
            for valid in 1..=8 {
                let mut message=std::vec![0x59;length];
                if let Some(last)=message.last_mut() { *last &= 0xff >> (8-valid); }
                let bits=Fips202BitString::new(&message,if length==0 {0}else{valid}).map_err(|_|KmacError::InvalidBitString)?;
                let key=Fips202BitString::new(&[0x13],5).map_err(|_|KmacError::InvalidBitString)?;
                let custom=Fips202BitString::new(&[0x05],3).map_err(|_|KmacError::InvalidBitString)?;
                let mut expected=[0;354];
                let mut reference=crate::$reference::new_bits_conformance(key,custom)?.finalize_bits_xof_conformance(bits)?;
                for chunk in expected.chunks_mut(118) { reference.squeeze_public(chunk,KmacPublicDeclassification::acknowledge())?; }
                if let Some(last)=expected.last_mut() { *last &= 0xff >> (8-valid); }
                let mut output=[0xa5;354];
                workspace.with_bits_conformance(key,custom,|mut state| {
                    let prefix=length.saturating_sub(1);
                    for chunk in message.get(..prefix).ok_or(KmacError::InvalidBitString)?.chunks(17) { state.update(chunk)?; }
                    let tail=Fips202BitString::new(message.get(prefix..).ok_or(KmacError::InvalidBitString)?,if length==0 {0}else{valid}).map_err(|_|KmacError::InvalidBitString)?;
                    let mut reader=state.finalize_bits_xof_conformance(tail)?;
                    let (first,rest)=output.split_at_mut(169);
                    let (middle,last)=rest.split_at_mut(168);
                    reader.squeeze_public(&mut [],KmacPublicDeclassification::acknowledge())?;
                    drop(reader.squeeze_secret(&mut [])?);
                    let first=reader.squeeze_secret(first)?;
                    assert_eq!(first.expose(),expected.get(..169).ok_or(KmacError::InvalidBitString)?);
                    drop(first);
                    reader.squeeze_public(middle,KmacPublicDeclassification::acknowledge())?;
                    let last=reader.squeeze_final_bits_secret(last,valid)?;
                    assert_eq!(last.expose(),expected.get(337..).ok_or(KmacError::InvalidBitString)?);
                    drop(last);
                    Ok::<(),KmacError>(())
                })??;
                assert_eq!(output.get(169..337),expected.get(169..337));
                assert!(output.get(..169).ok_or(KmacError::InvalidBitString)?.iter().all(|b|*b==0));
                assert!(output.get(337..).ok_or(KmacError::InvalidBitString)?.iter().all(|b|*b==0));
                assert!(workspace.metadata_cleared());
            }
        }
        assert!(matches!(workspace.with_conformance(b"",b"",|state|state.finalize_xof().map(|_|()))?,Err(KmacError::KeyTooShort)));
        workspace.with_conformance(b"",b"",|state|state.finalize_xof_conformance()?.squeeze_final_bits_public(&mut [],0,KmacPublicDeclassification::acknowledge()))??;
    }}; }
    check!(KmacXof128Workspace, KmacXof128);
    check!(KmacXof256Workspace, KmacXof256);
    Ok(())
}
