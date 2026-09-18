extern crate std;
use super::*;
use crate::{Fips202Output, TupleHashError as Error, TupleHashPublicDeclassification as Public};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    vec,
};

fn bits(bytes: &[u8], valid: u8) -> Result<Fips202BitString<'_>, Error> {
    Fips202BitString::new(bytes, valid).map_err(|_| Error::InvalidBitString)
}
macro_rules! checks {
    ($comparison:ident, $lifecycle:ident, $workspace:ident, $ordinary:ident, $rate:literal) => {
        #[test]
        fn $comparison() -> Result<(), Error> {
            let mut workspace = $workspace::new();
            for length in [0, 1, $rate - 1, $rate, $rate + 1, 2 * $rate + 1] {
                for tail in 1..=8 {
                    let mut input = vec![0xa5; length];
                    if let Some(last) = input.last_mut() {
                        *last &= u8::MAX >> (8 - tail);
                    }
                    let valid = if length == 0 { 0 } else { tail };
                    for width in [0, 1, 32, $rate + 1, 2 * $rate + 1] {
                        let output_valid = if width == 0 { 0 } else { tail };
                        let mut expected = vec![0; width];
                        let custom = bits(&[5], 3)?;
                        let mut reference = crate::$ordinary::new_bits(custom)?;
                        reference.push_item_bits(bits(&[3], 2)?)?;
                        reference.push_item(&[])?;
                        reference.push_item_bits(bits(&input, valid)?)?;
                        reference.finalize_xof()?.squeeze_final_bits(
                            Fips202Output::new(&mut expected, output_valid)
                                .map_err(|_| Error::InvalidBitString)?,
                        )?;
                        let mut actual = vec![0x55; width];
                        workspace.with_bits(custom, |mut state| {
                            state.push_item_bits(bits(&[3], 2)?)?;
                            state.begin_item(0)?.finish()?;
                            let item = bits(&input, valid)?;
                            let mut writer = state.begin_item(
                                u128::try_from(item.bit_len())
                                    .map_err(|_| Error::MessageTooLong)?,
                            )?;
                            writer.update_bits(item)?;
                            writer.finish()?;
                            let mut reader = state.finalize_xof()?;
                            reader.squeeze_public(&mut [], Public::acknowledge())?;
                            drop(reader.squeeze_secret(&mut [])?);
                            let split = width.saturating_sub(1);
                            let (prefix, last) = actual.split_at_mut(split);
                            for (index, chunk) in prefix.chunks_mut(17).enumerate() {
                                if index % 2 == 0 {
                                    reader.squeeze_public(chunk, Public::acknowledge())?;
                                } else {
                                    let secret = reader.squeeze_secret(chunk)?;
                                    let start =
                                        index.checked_mul(17).ok_or(Error::OutputTooLong)?;
                                    let end = start
                                        .checked_add(secret.expose().len())
                                        .ok_or(Error::OutputTooLong)?;
                                    let known =
                                        expected.get(start..end).ok_or(Error::InvalidBitString)?;
                                    assert_eq!(secret.expose(), known);
                                    drop(secret);
                                    assert!(chunk.iter().all(|byte| *byte == 0));
                                    // Restore known public oracle bytes, not secret output.
                                    chunk.copy_from_slice(known);
                                }
                            }
                            reader.squeeze_final_bits_public(
                                last,
                                output_valid,
                                Public::acknowledge(),
                            )
                        })??;
                        assert_eq!(actual, expected);
                        assert!(workspace.metadata_cleared());
                        actual.fill(0xa5);
                        let secret = workspace.with_bits(custom, |mut state| {
                            state.push_item_bits(bits(&[3], 2)?)?;
                            state.push_item(&[])?;
                            state.push_item_bits(bits(&input, valid)?)?;
                            state
                                .finalize_xof()?
                                .squeeze_final_bits_secret(&mut actual, output_valid)
                        })??;
                        assert_eq!(secret.expose(), expected);
                        assert!(workspace.metadata_cleared());
                        drop(secret);
                        assert!(actual.iter().all(|byte| *byte == 0));
                    }
                }
            }
            Ok(())
        }
        #[test]
        fn $lifecycle() -> Result<(), Error> {
            let mut workspace = $workspace::new();
            for action in 0..6 {
                workspace.with(b"custom", |mut state| -> Result<(), Error> {
                    state.push_item(b"secret")?;
                    let mut writer = state.begin_item(8)?;
                    match action {
                        0 => drop(writer),
                        1 => writer.cancel(),
                        2 => core::mem::forget(writer),
                        3 => {
                            writer.update(b"x")?;
                            core::mem::forget(writer);
                        }
                        4 => {
                            assert!(writer.finish().is_err());
                        }
                        _ => {
                            assert!(writer.update(b"xx").is_err());
                            drop(writer);
                        }
                    }
                    assert!(state.finalize_xof().is_err());
                    Ok(())
                })??;
                assert!(workspace.metadata_cleared());
            }
            for action in 0..4 {
                let outcome = catch_unwind(AssertUnwindSafe(|| {
                    workspace.with(b"custom", |mut state| -> Result<(), Error> {
                        state.push_item(b"secret")?;
                        let mut reader = state.finalize_xof()?;
                        let mut bytes = [0xa5; 3];
                        drop(reader.squeeze_secret(&mut bytes)?);
                        assert_eq!(bytes, [0; 3]);
                        match action {
                            0 => drop(reader),
                            1 => reader.cancel(),
                            2 => core::mem::forget(reader),
                            _ => panic!("reader unwind"),
                        }
                        Ok(())
                    })
                }));
                if action == 3 {
                    assert!(outcome.is_err());
                } else {
                    assert!(matches!(outcome, Ok(Ok(Ok(())))));
                }
                assert!(workspace.metadata_cleared());
            }
            for valid in [0, 9, 255] {
                let mut bytes = [0xa5; 3];
                let result = workspace.with(b"", |state| {
                    state
                        .finalize_xof()?
                        .squeeze_final_bits_secret(&mut bytes, valid)
                })?;
                assert_eq!(result.map(drop), Err(Error::InvalidBitString));
                assert_eq!(bytes, [0; 3]);
                bytes.fill(0x55);
                assert_eq!(
                    workspace.with(b"", |state| state
                        .finalize_xof()?
                        .squeeze_final_bits_public(&mut bytes, valid, Public::acknowledge()))?,
                    Err(Error::InvalidBitString)
                );
                assert_eq!(bytes, [0x55; 3]);
                assert!(workspace.metadata_cleared());
            }
            workspace.with(b"", |state| state.cancel())?;
            assert!(workspace.metadata_cleared());
            workspace.with(b"", |state| core::mem::forget(state))?;
            assert!(workspace.metadata_cleared());
            workspace.with(b"", |mut state| {
                state.push_item(b"reused")?;
                state
                    .finalize_xof()?
                    .squeeze_final_bits_public(&mut [], 0, Public::acknowledge())
            })??;
            Ok(())
        }
    };
}
checks!(
    scoped_tuplexof128_differential,
    scoped_tuplexof128_lifecycle,
    TupleHashXof128Workspace,
    TupleHashXof128,
    168
);
checks!(
    scoped_tuplexof256_differential,
    scoped_tuplexof256_lifecycle,
    TupleHashXof256Workspace,
    TupleHashXof256,
    136
);
