extern crate std;
use super::{TupleHash128Workspace, TupleHash256Workspace};
use crate::{
    Fips202BitString, Fips202Output, TupleHash128, TupleHash256, TupleHashError as Error,
    TupleHashPublicDeclassification as Public,
};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    vec,
};

fn bits(input: &[u8], valid: u8) -> Fips202BitString<'_> {
    let result = Fips202BitString::new(input, valid);
    assert!(result.is_ok());
    match result {
        Ok(value) => value,
        Err(_) => unreachable!(),
    }
}

macro_rules! comparisons {
    ($test:ident, $workspace:ident, $ordinary:ident, $rate:literal) => {
        #[test]
        fn $test() -> Result<(), Error> {
            let mut workspace = $workspace::new();
            for length in [0, 1, $rate - 1, $rate, $rate + 1, 2 * $rate + 1, 1024] {
                for tail in 1..=8 {
                    let mut input = vec![0xa5; length];
                    if let Some(last) = input.last_mut() {
                        *last &= u8::MAX >> (8 - tail);
                    }
                    let valid = if length == 0 { 0 } else { tail };
                    let item = bits(&input, valid);
                    for width in [0, 1, 32, $rate + 1, 2 * $rate + 1] {
                        let output_valid = if width == 0 { 0 } else { tail };
                        let mut expected = vec![0; width];
                        let custom = bits(&[5], 3);
                        let mut reference = $ordinary::new_bits(custom)?;
                        reference.push_item_bits(bits(&[3], 2))?;
                        reference.push_item(&[])?;
                        reference.push_item_bits(item)?;
                        reference.push_item_bits(bits(&[5], 3))?;
                        reference.finalize_bits(
                            Fips202Output::new(&mut expected, output_valid)
                                .map_err(|_| Error::InvalidBitString)?,
                        )?;
                        let mut actual = vec![0x55; width];
                        workspace.with_bits(custom, |mut state| {
                            state.push_item_bits(bits(&[3], 2))?;
                            state.push_item(&[])?;
                            state.push_item_bits(item)?;
                            state.push_item_bits(bits(&[5], 3))?;
                            state.finalize_public_bits(
                                &mut actual,
                                output_valid,
                                Public::acknowledge(),
                            )
                        })??;
                        assert_eq!(actual, expected);
                        assert!(workspace.metadata_cleared());
                        actual.fill(0xa5);
                        let output = workspace.with_bits(custom, |mut state| {
                            state.push_item_bits(bits(&[3], 2))?;
                            state.begin_item(0)?.finish()?;
                            let mut writer = state.begin_item(
                                u128::try_from(item.bit_len())
                                    .map_err(|_| Error::MessageTooLong)?,
                            )?;
                            let split = if valid == 0 || valid == 8 {
                                length
                            } else {
                                length - 1
                            };
                            let prefix = input.get(..split).ok_or(Error::InvalidBitString)?;
                            for chunk in prefix.chunks(17) {
                                writer.update(&[])?;
                                writer.update(chunk)?;
                            }
                            if split != length {
                                writer.update_bits(bits(
                                    input.get(split..).ok_or(Error::InvalidBitString)?,
                                    valid,
                                ))?;
                            }
                            writer.finish()?;
                            state.push_item_bits(bits(&[5], 3))?;
                            state.finalize_secret_bits(&mut actual, output_valid)
                        })??;
                        assert_eq!(output.expose(), expected);
                        assert!(workspace.metadata_cleared());
                        drop(output);
                        assert!(actual.iter().all(|b| *b == 0));
                    }
                }
            }
            Ok(())
        }
    };
}
comparisons!(
    scoped_tuple128_matches_portable_bits_and_streaming,
    TupleHash128Workspace,
    TupleHash128,
    168
);
comparisons!(
    scoped_tuple256_matches_portable_bits_and_streaming,
    TupleHash256Workspace,
    TupleHash256,
    136
);

macro_rules! lifecycle {
    ($test:ident, $workspace:ident, $ordinary:ident) => {
        #[test]
        fn $test() -> Result<(), Error> {
            let mut workspace = $workspace::new();
            let mut reference = $ordinary::new(b"")?;
            reference.push_item_bits(bits(&[0x5d, 0x15], 5))?;
            let mut expected = [0; 32];
            reference.finalize(&mut expected)?;
            let mut output = [0x55; 32];
            workspace.with(b"", |mut state| {
                let mut writer = state.begin_item(13)?;
                writer.update_bits(bits(&[5], 3))?;
                writer.update_bits(bits(&[3], 2))?;
                writer.update_bits(bits(&[0xaa], 8))?;
                writer.finish()?;
                state.finalize_public(&mut output, Public::acknowledge())
            })??;
            assert_eq!(output, expected);
            for mode in 0..5 {
                workspace.with(b"private custom", |mut state| -> Result<(), Error> {
                    state.push_item(b"secret")?;
                    let mut writer = state.begin_item(16)?;
                    writer.update(b"x")?;
                    match mode {
                        0 => drop(writer),
                        1 => writer.cancel(),
                        2 => core::mem::forget(writer),
                        3 => {
                            assert_eq!(writer.finish(), Err(Error::IncompleteItem));
                        }
                        _ => {
                            assert_eq!(writer.update(b"yz"), Err(Error::MessageTooLong));
                            drop(writer);
                        }
                    }
                    if mode != 2 {
                        assert!(state.terminal_and_cleared());
                    }
                    assert!(state.push_item(b"cannot resume").is_err());
                    output.fill(0xa5);
                    assert!(state.finalize_secret(&mut output).is_err());
                    assert_eq!(output, [0; 32]);
                    Ok(())
                })??;
                assert!(workspace.metadata_cleared());
            }
            // A forgotten *complete but unfinished* writer must not authorize output.
            for secret in [false, true] {
                workspace.with(b"", |mut state| -> Result<(), Error> {
                    let mut writer = state.begin_item(8)?;
                    writer.update(b"x")?;
                    core::mem::forget(writer);
                    output.fill(0xa5);
                    if secret {
                        assert!(state.finalize_secret(&mut output).is_err());
                        assert_eq!(output, [0; 32]);
                    } else {
                        assert_eq!(
                            state.finalize_public(&mut output, Public::acknowledge()),
                            Err(Error::IncompleteItem)
                        );
                        assert_eq!(output, [0xa5; 32]);
                    }
                    Ok(())
                })??;
            }
            for valid in [0, 9, 255] {
                output.fill(0xa5);
                workspace.with(b"", |state| {
                    assert!(state.finalize_secret_bits(&mut output, valid).is_err());
                })?;
                assert_eq!(output, [0; 32]);
                output.fill(0xa5);
                workspace.with(b"", |state| {
                    assert_eq!(
                        state.finalize_public_bits(&mut output, valid, Public::acknowledge()),
                        Err(Error::InvalidBitString)
                    );
                })?;
                assert_eq!(output, [0xa5; 32]);
            }
            for mode in 0..3 {
                let caught = catch_unwind(AssertUnwindSafe(|| {
                    workspace.with(b"secret", |mut state| {
                        assert!(state.push_item_bits(bits(&[5], 3)).is_ok());
                        match mode {
                            0 => state.cancel(),
                            1 => core::mem::forget(state),
                            _ => {
                                core::mem::forget(state);
                                std::panic::resume_unwind(std::boxed::Box::new(()));
                            }
                        }
                    })
                }));
                assert_eq!(caught.is_err(), mode == 2);
                assert!(workspace.metadata_cleared());
                workspace.with(b"", |mut state| {
                    state.push_item_bits(bits(&[0x5d, 0x15], 5))?;
                    state.finalize_public(&mut output, Public::acknowledge())
                })??;
                assert_eq!(output, expected);
            }
            workspace.with(b"", |mut state| {
                assert!(state.begin_item(u128::MAX).is_err());
                assert_eq!(state.push_item(b"later"), Err(Error::StateConsumed));
            })?;
            assert!(workspace.metadata_cleared());
            Ok(())
        }
    };
}
lifecycle!(
    scoped_tuple128_terminal_writer_and_output_lifecycle,
    TupleHash128Workspace,
    TupleHash128
);
lifecycle!(
    scoped_tuple256_terminal_writer_and_output_lifecycle,
    TupleHash256Workspace,
    TupleHash256
);
