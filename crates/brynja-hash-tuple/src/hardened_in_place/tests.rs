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

// Only interpreted runs accept case selection. Native tests retain the whole
// matrix and its cross-case workspace reuse, even with hostile environment input.
pub(super) fn miri_selection(total: usize) -> (Option<usize>, Option<usize>) {
    let selected = if cfg!(miri) {
        std::env::var("BRYNJA_MIRI_CASE").ok().map(|value| {
            let parsed = value.parse::<usize>();
            assert!(parsed.is_ok());
            parsed.unwrap_or(usize::MAX)
        })
    } else {
        None
    };
    assert!(selected.is_none_or(|case| case < total));
    let width = if let Some(case) = selected {
        let profile = std::env::var("BRYNJA_MIRI_PROFILE");
        assert!(matches!(profile.as_deref(), Ok("routine" | "extended")));
        if profile.as_deref() == Ok("routine") {
            // Empty-input cases must have nonempty output, so their tail width
            // is exercised rather than disappearing on both sides of the test.
            Some((case % 8).saturating_add(1) % 5)
        } else {
            None
        }
    } else {
        None
    };
    (selected, width)
}

pub(super) fn miri_complete(
    selected: Option<usize>,
    visited: usize,
    executed: usize,
    total: usize,
    width: Option<usize>,
    _name: &str,
) {
    assert_eq!(visited, total);
    assert!(width.is_none_or(|index| index < 5 && selected.is_some()));
    // Native/extended retain the whole width product; routine covers every
    // dimension without the product, with its exact width selected above.
    let expected = if selected.is_some() {
        Some(if width.is_some() { 1 } else { 5 })
    } else {
        total.checked_mul(5)
    };
    assert_eq!(Some(executed), expected);
    #[cfg(miri)]
    if let Some(case) = selected {
        std::println!("\nMIRI_CASE_PASS: {_name}:{case}");
    }
}

#[test]
fn miri_chunks_reject_incomplete_or_duplicate_output_widths() {
    miri_complete(None, 48, 240, 48, None, "accounting");
    assert!(
        catch_unwind(|| {
            miri_complete(None, usize::MAX, 0, usize::MAX, None, "overflow");
        })
        .is_err()
    );
    for (selected, visited, executed) in [
        (Some(0), 47, 5),
        (Some(0), 48, 0),
        (Some(0), 48, 4),
        (Some(0), 48, 6),
        (None, 48, 239),
        (None, 48, 241),
    ] {
        assert!(
            catch_unwind(|| {
                miri_complete(selected, visited, executed, 48, None, "accounting");
            })
            .is_err()
        );
    }
    for (selected, executed, width) in [
        (Some(0), 0, 0),
        (Some(0), 2, 0),
        (Some(0), 1, 5),
        (None, 240, 0),
    ] {
        assert!(
            catch_unwind(|| miri_complete(selected, 48, executed, 48, Some(width), "accounting"))
                .is_err()
        );
    }
}

macro_rules! comparisons {
    ($test:ident, $workspace:ident, $ordinary:ident, $rate:literal) => {
        #[test]
        fn $test() -> Result<(), Error> {
            let (selected, output_width) = miri_selection(56);
            let mut visited = 0usize;
            let mut executed = 0usize;
            let mut workspace = $workspace::new();
            for length in [0, 1, $rate - 1, $rate, $rate + 1, 2 * $rate + 1, 1024] {
                for tail in 1..=8 {
                    let case = visited;
                    visited = visited.checked_add(1).ok_or(Error::StateConsumed)?;
                    if selected.is_some_and(|wanted| wanted != case) {
                        continue;
                    }
                    let mut input = vec![0xa5; length];
                    if let Some(last) = input.last_mut() {
                        *last &= u8::MAX >> (8 - tail);
                    }
                    let valid = if length == 0 { 0 } else { tail };
                    let item = bits(&input, valid);
                    for (index, width) in
                        [0, 1, 32, $rate + 1, 2 * $rate + 1].into_iter().enumerate()
                    {
                        if output_width.is_some_and(|wanted| wanted != index) {
                            continue;
                        }
                        executed = executed.checked_add(1).ok_or(Error::StateConsumed)?;
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
            miri_complete(
                selected,
                visited,
                executed,
                56,
                output_width,
                stringify!($test),
            );
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
