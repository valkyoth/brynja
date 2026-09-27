use super::*;
use crate::{
    Fips202Output, ParallelHashError as Error, ParallelHashPublicDeclassification as Public,
};

macro_rules! check {
    ($test:ident, $workspace:ident, $ordinary:ident) => {
        #[test]
        fn $test() -> Result<(), Error> {
            let (selected, bounded) = miri_selection(40)?;
            let mut visited = 0;
            let mut executed = 0;
            let mut workspace = $workspace::new();
            for b in [1, 7, 8, 136, 168] {
                for valid in 1..=8 {
                    let index = visited;
                    visited += 1;
                    if selected.is_some_and(|case| case != index) {
                        continue;
                    }
                    executed += 1;
                    let bytes = [0x35; 173];
                    let length = if bounded {
                        (2 * b + 1).min(bytes.len())
                    } else {
                        bytes.len()
                    };
                    let input = bytes.get(..length).ok_or(Error::StateConsumed)?;
                    let mut storage = [0xa5; 168];
                    let block = storage.get_mut(..b).ok_or(Error::StateConsumed)?;
                    let tail =
                        Fips202BitString::new(&[1], valid).map_err(|_| Error::InvalidBitString)?;
                    let custom =
                        Fips202BitString::new(&[3], 2).map_err(|_| Error::InvalidBitString)?;
                    let mut reference_storage = [0; 168];
                    let mut reference = crate::$ordinary::new_bits(
                        reference_storage.get_mut(..b).ok_or(Error::StateConsumed)?,
                        custom,
                    )?;
                    reference.update(&input)?;
                    let mut expected = [0; 511];
                    reference.finalize_bits_xof(tail)?.squeeze_final_bits(
                        Fips202Output::new(&mut expected, valid)
                            .map_err(|_| Error::InvalidBitString)?,
                    )?;
                    let mut final_output = [0xa5; 174];
                    let last = workspace.with_bits(block, custom, |mut state| {
                        for chunk in input.chunks(13) {
                            state.update(chunk)?;
                        }
                        let mut reader = state.finalize_bits_xof(tail)?;
                        reader.squeeze_public(&mut [], Public::acknowledge())?;
                        drop(reader.squeeze_secret(&mut [])?);
                        let mut first = [0xa5; 169];
                        reader.squeeze_public(&mut first, Public::acknowledge())?;
                        assert_eq!(
                            first.as_slice(),
                            expected.get(..169).ok_or(Error::StateConsumed)?
                        );
                        let mut middle = [0xa5; 168];
                        let secret = reader.squeeze_secret(&mut middle)?;
                        assert_eq!(
                            secret.expose(),
                            expected.get(169..337).ok_or(Error::StateConsumed)?
                        );
                        drop(secret);
                        assert_eq!(middle, [0; 168]);
                        reader.squeeze_final_bits_secret(&mut final_output, valid)
                    })??;
                    assert_eq!(
                        last.expose(),
                        expected.get(337..).ok_or(Error::StateConsumed)?
                    );
                    assert!(block.iter().all(|byte| *byte == 0));
                    drop(last);
                    assert_eq!(final_output, [0; 174]);
                    assert!(workspace.cleared());
                    let mut public = [0xa5; 511];
                    workspace.with_bits(block, custom, |mut state| {
                        state.update(&input)?;
                        state.finalize_bits_xof(tail)?.squeeze_final_bits_public(
                            &mut public,
                            valid,
                            Public::acknowledge(),
                        )
                    })??;
                    assert_eq!(public, expected);
                }
            }
            // The matrix-independent lifecycle checks below belong to case 0.
            // Native execution still reaches them once, after the full matrix.
            if selected.is_some_and(|case| case != 0) {
                miri_complete(selected, visited, executed, 40, stringify!($test));
                return Ok(());
            }
            let mut block = [0xa5; 8];
            for action in 0..3 {
                workspace.with(&mut block, b"", |mut state| {
                    state.update(b"pending")?;
                    if action == 0 {
                        state.cancel();
                    } else {
                        let mut reader = state.finalize_xof()?;
                        reader.squeeze_public(&mut [0; 169], Public::acknowledge())?;
                        if action == 1 {
                            reader.cancel();
                        } else {
                            core::mem::forget(reader);
                        }
                    }
                    Ok::<(), Error>(())
                })??;
                assert_eq!(block, [0; 8]);
                assert!(workspace.cleared());
            }
            for valid in [0, 9, 255] {
                let mut output = [0xa5; 3];
                assert!(
                    workspace
                        .with(&mut block, b"", |state| state
                            .finalize_xof()?
                            .squeeze_final_bits_public(
                                &mut output,
                                valid,
                                Public::acknowledge()
                            ))?
                        .is_err()
                );
                assert_eq!(output, [0xa5; 3]);
                assert!(
                    workspace
                        .with(&mut block, b"", |state| state
                            .finalize_xof()?
                            .squeeze_final_bits_secret(&mut output, valid))?
                        .is_err()
                );
                assert_eq!(output, [0; 3]);
                assert!(workspace.cleared());
            }
            let mut entered = false;
            assert!(workspace.with(&mut [], b"", |_| entered = true).is_err());
            assert!(!entered);
            workspace.with(&mut block, b"", |state| {
                state
                    .finalize_xof()?
                    .squeeze_final_bits_public(&mut [], 0, Public::acknowledge())
            })??;
            drop(workspace.with(&mut block, b"", |state| {
                state.finalize_xof()?.squeeze_final_bits_secret(&mut [], 0)
            })??);
            miri_complete(selected, visited, executed, 40, stringify!($test));
            Ok(())
        }
    };
}
check!(
    scoped_parallel_xof128_matches_and_clears,
    ParallelHashXof128Workspace,
    ParallelHashXof128
);
check!(
    scoped_parallel_xof256_matches_and_clears,
    ParallelHashXof256Workspace,
    ParallelHashXof256
);

// Native execution always traverses the complete original matrix. These
// interpreted environment selectors are used only by exact Miri tasks.
#[cfg(not(miri))]
fn miri_selection(_total: usize) -> Result<(Option<usize>, bool), Error> {
    Ok((None, false))
}

#[cfg(miri)]
fn miri_selection(total: usize) -> Result<(Option<usize>, bool), Error> {
    extern crate std;
    let selected = std::env::var("BRYNJA_MIRI_CASE")
        .ok()
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|_| Error::StateConsumed)?;
    assert!(selected.is_none_or(|case| case < total));
    let profile_value = std::env::var("BRYNJA_MIRI_PROFILE").ok();
    let profile = profile_value.as_deref();
    assert!(matches!(profile, None | Some("routine") | Some("extended")));
    let bounded = profile == Some("routine");
    assert!(!bounded || selected.is_some());
    Ok((selected, bounded))
}

fn miri_complete(
    selected: Option<usize>,
    visited: usize,
    executed: usize,
    total: usize,
    _name: &str,
) {
    assert_eq!(visited, total);
    assert_eq!(executed, if selected.is_some() { 1 } else { total });
    #[cfg(miri)]
    if let Some(case) = selected {
        extern crate std;
        std::println!("\nMIRI_CASE_PASS: {_name}:{case}");
    }
}
