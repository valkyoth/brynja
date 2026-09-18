use super::native::{bad, owner, session};
use brynja_hash_tuple::{
    Fips202BitString, Fips202Output, TupleHashError as Error,
    TupleHashPublicDeclassification as Public, execution::in_place as api,
};
use std::{
    io,
    panic::{AssertUnwindSafe, catch_unwind},
};

macro_rules! check {
    ($compare:ident, $lifecycle:ident, $workspace:ident, $ordinary:ident) => {
        #[test]
        fn $compare() -> Result<(), io::Error> {
            let authority = owner()?;
            let mut workspace = api::$workspace::new(session(&authority)?).map_err(bad)?;
            for width in [0, 1, 135, 136, 137, 167, 168, 169, 337] {
                for valid in if width == 0 { 0..=0 } else { 1..=8 } {
                    let mut expected = vec![0; width];
                    let custom = Fips202BitString::new(&[5], 3).map_err(bad)?;
                    let mut reference =
                        brynja_hash_tuple::$ordinary::new_bits(custom).map_err(bad)?;
                    reference.push_item_bits(custom).map_err(bad)?;
                    reference.push_item(b"").map_err(bad)?;
                    reference.push_item(b"secret message").map_err(bad)?;
                    reference
                        .finalize_xof()
                        .map_err(bad)?
                        .squeeze_final_bits(Fips202Output::new(&mut expected, valid).map_err(bad)?)
                        .map_err(bad)?;
                    let mut actual = vec![0xa5; width];
                    workspace
                        .with_bits(custom, |mut state| -> Result<(), Error> {
                            state.push_item_bits(custom)?;
                            state.push_item(b"")?;
                            let mut writer = state.begin_item(112)?;
                            writer.update(b"secret ")?;
                            writer.update(b"message")?;
                            writer.finish()?;
                            let mut reader = state.finalize_xof()?;
                            let prefix = width.saturating_sub(1);
                            for (index, chunk) in actual[..prefix].chunks_mut(17).enumerate() {
                                if index % 2 == 0 {
                                    reader.squeeze_public(chunk, Public::acknowledge())?;
                                } else {
                                    let offset = index * 17;
                                    let end = offset + chunk.len();
                                    let secret = reader.squeeze_secret(chunk)?;
                                    assert_eq!(secret.expose(), &expected[offset..end]);
                                    drop(secret);
                                    assert!(chunk.iter().all(|byte| *byte == 0));
                                    // Restore known public oracle bytes, never copy a secret owner.
                                    chunk.copy_from_slice(&expected[offset..end]);
                                }
                            }
                            reader.squeeze_final_bits_public(
                                &mut actual[prefix..],
                                valid,
                                Public::acknowledge(),
                            )
                        })
                        .map_err(bad)?
                        .map_err(bad)?;
                    assert_eq!(actual, expected);
                    let secret = workspace
                        .with_bits(custom, |mut state| {
                            state.push_item_bits(custom)?;
                            state.push_item(b"")?;
                            state.push_item(b"secret message")?;
                            state
                                .finalize_xof()?
                                .squeeze_final_bits_secret(&mut actual, valid)
                        })
                        .map_err(bad)?
                        .map_err(bad)?;
                    assert_eq!(secret.expose(), expected);
                    drop(secret);
                    assert!(actual.iter().all(|byte| *byte == 0));
                }
            }
            let mut scratch = [0x55; 350];
            let mut output = [0xa5; 337];
            workspace
                .with_scratch(b"", &mut scratch, |state| {
                    state
                        .finalize_xof()?
                        .squeeze_public(&mut output, Public::acknowledge())
                })
                .map_err(bad)?
                .map_err(bad)?;
            let mut expected = [0; 337];
            let mut ordinary = brynja_hash_tuple::$ordinary::new(b"").map_err(bad)?;
            ordinary
                .finalize_xof()
                .map_err(bad)?
                .squeeze(&mut expected)
                .map_err(bad)?;
            assert_eq!(output, expected);
            assert_eq!(scratch, [0; 350]);
            assert_eq!(workspace.report(), authority.report());
            Ok(())
        }

        #[test]
        fn $lifecycle() -> Result<(), io::Error> {
            let authority = owner()?;
            let mut workspace = api::$workspace::new(session(&authority)?).map_err(bad)?;
            for abandon in 0..3 {
                workspace
                    .with(b"", |mut state| -> Result<(), Error> {
                        let mut writer = state.begin_item(8)?;
                        if abandon == 2 {
                            writer.update(&[1])?;
                        }
                        if abandon == 0 {
                            drop(writer);
                        } else {
                            core::mem::forget(writer);
                        }
                        assert!(state.finalize_xof().is_err());
                        Ok(())
                    })
                    .map_err(bad)?
                    .map_err(bad)?;
            }
            let mut output = [0xa5; 337];
            workspace
                .with(b"", |state| -> Result<(), Error> {
                    let mut reader = state.finalize_xof()?;
                    assert!(
                        reader
                            .squeeze_public(&mut output, Public::acknowledge())
                            .is_err()
                    );
                    assert_eq!(output, [0xa5; 337]);
                    assert!(
                        reader
                            .squeeze_public(&mut [], Public::acknowledge())
                            .is_err()
                    );
                    assert!(reader.squeeze_secret(&mut output).is_err());
                    assert_eq!(output, [0; 337]);
                    Ok(())
                })
                .map_err(bad)?
                .map_err(bad)?;
            for valid in [0, 9, 255] {
                output.fill(0xa5);
                assert!(
                    workspace
                        .with(b"", |state| state
                            .finalize_xof()?
                            .squeeze_final_bits_public(
                                &mut output,
                                valid,
                                Public::acknowledge()
                            ))
                        .map_err(bad)?
                        .is_err()
                );
                assert_eq!(output, [0xa5; 337]);
                assert!(
                    workspace
                        .with(b"", |state| state
                            .finalize_xof()?
                            .squeeze_final_bits_secret(&mut output, valid))
                        .map_err(bad)?
                        .is_err()
                );
                assert_eq!(output, [0; 337]);
            }
            for action in 0..4 {
                let mut scratch = [0x55; 350];
                let result = catch_unwind(AssertUnwindSafe(|| {
                    workspace.with_scratch(b"", &mut scratch, |state| -> Result<(), Error> {
                        let mut reader = state.finalize_xof()?;
                        reader.squeeze_public(&mut output, Public::acknowledge())?;
                        match action {
                            0 => drop(reader),
                            1 => reader.cancel(),
                            2 => core::mem::forget(reader),
                            _ => panic!("test reader unwind"),
                        }
                        Ok(())
                    })
                }));
                if action == 3 {
                    assert!(result.is_err());
                } else {
                    result.map_err(bad)?.map_err(bad)?.map_err(bad)?;
                }
                assert_eq!(scratch, [0; 350]);
                let secret = workspace
                    .with(b"", |state| {
                        state.finalize_xof()?.squeeze_secret(&mut output)
                    })
                    .map_err(bad)?
                    .map_err(bad)?;
                drop(secret);
                assert_eq!(output, [0; 337]);
            }
            workspace
                .with(b"", |state| -> Result<(), Error> {
                    let mut reader = state.finalize_xof()?;
                    authority.quarantine();
                    output.fill(0xa5);
                    assert!(
                        reader
                            .squeeze_public(&mut output[..8], Public::acknowledge())
                            .is_err()
                    );
                    assert_eq!(output, [0xa5; 337]);
                    assert!(reader.squeeze_secret(&mut output).is_err());
                    assert_eq!(output, [0; 337]);
                    assert!(reader.squeeze_secret(&mut []).is_err());
                    Ok(())
                })
                .map_err(bad)?
                .map_err(bad)?;
            let mut scratch = [0x55; 350];
            let mut entered = false;
            assert!(
                workspace
                    .with_scratch(b"", &mut scratch, |_| {
                        entered = true;
                    })
                    .is_err()
            );
            assert!(!entered);
            assert_eq!(scratch, [0; 350]);
            Ok(())
        }
    };
}
check!(
    xof128_mixed_output,
    xof128_lifecycle,
    TupleHashXof128Workspace,
    TupleHashXof128
);
check!(
    xof256_mixed_output,
    xof256_lifecycle,
    TupleHashXof256Workspace,
    TupleHashXof256
);
