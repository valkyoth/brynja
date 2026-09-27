use super::*;
use crate::{
    Fips202BitString, Fips202Output, ParallelHashError as Error,
    ParallelHashPublicDeclassification as Public,
};

macro_rules! check {
    ($test:ident, $workspace:ident, $ordinary:ident) => {
        #[test]
        fn $test() -> Result<(), Error> {
            let (selected, bounded) = miri_selection(48)?;
            let mut visited = 0;
            let mut executed = 0;
            let mut workspace = $workspace::new();
            for b in [1, 7, 8, 17, 136, 168] {
                let mut storage = [0xa5; 168];
                let block = storage.get_mut(..b).ok_or(Error::StateConsumed)?;
                for bits in 1..=8 {
                    let index = visited;
                    visited += 1;
                    if selected.is_some_and(|case| case != index) {
                        continue;
                    }
                    executed += 1;
                    let bytes = [0x05; 177];
                    let length = if bounded {
                        (2 * b + 1).min(bytes.len())
                    } else {
                        bytes.len()
                    };
                    let input = bytes.get(..length).ok_or(Error::StateConsumed)?;
                    let tail =
                        Fips202BitString::new(&[1], bits).map_err(|_| Error::InvalidBitString)?;
                    let custom =
                        Fips202BitString::new(&[3], 2).map_err(|_| Error::InvalidBitString)?;
                    let mut expected = [0; 37];
                    let mut ref_block = [0; 168];
                    let mut reference = crate::$ordinary::new_bits(
                        ref_block.get_mut(..b).ok_or(Error::StateConsumed)?,
                        custom,
                    )?;
                    reference.update(&input)?;
                    reference.finalize_bits(
                        tail,
                        Fips202Output::new(&mut expected, bits)
                            .map_err(|_| Error::InvalidBitString)?,
                    )?;
                    let mut output = [0xa5; 37];
                    workspace.with_bits(block, custom, |mut state| {
                        for chunk in input.chunks(13) {
                            state.update(chunk)?;
                        }
                        state.finalize_bits_public(tail, &mut output, bits, Public::acknowledge())
                    })??;
                    assert_eq!(output, expected);
                    assert!(block.iter().all(|byte| *byte == 0));
                    assert!(workspace.cleared());
                    let secret = workspace.with_bits(block, custom, |mut state| {
                        state.update(&input)?;
                        state.finalize_bits_secret(tail, &mut output, bits)
                    })??;
                    assert_eq!(secret.expose(), expected);
                    drop(secret);
                    assert_eq!(output, [0; 37]);
                    assert!(workspace.cleared());
                }
            }
            // The matrix-independent lifecycle checks below belong to case 0.
            // Native execution still reaches them once, after the full matrix.
            if selected.is_some_and(|case| case != 0) {
                miri_complete(selected, visited, executed, 48, stringify!($test));
                return Ok(());
            }
            let mut block = [0xa5; 7];
            for action in 0..2 {
                workspace.with(&mut block, b"", |mut state| {
                    state.update(b"pending")?;
                    if action == 0 {
                        state.cancel();
                    } else {
                        core::mem::forget(state);
                    }
                    Ok::<(), Error>(())
                })??;
                assert_eq!(block, [0; 7]);
                assert!(workspace.cleared());
            }
            for valid in [0, 9, 255] {
                let mut output = [0xa5; 17];
                assert!(
                    workspace
                        .with(&mut block, b"", |state| state.finalize_public_bits(
                            &mut output,
                            valid,
                            Public::acknowledge()
                        ))?
                        .is_err()
                );
                assert_eq!(output, [0xa5; 17]);
                assert!(
                    workspace
                        .with(&mut block, b"", |state| state
                            .finalize_secret_bits(&mut output, valid))?
                        .is_err()
                );
                assert_eq!(output, [0; 17]);
                assert!(workspace.cleared());
            }
            let mut entered = false;
            assert!(workspace.with(&mut [], b"", |_| entered = true).is_err());
            assert!(!entered);
            workspace.with(&mut block, b"", |state| {
                state.finalize_public(&mut [], Public::acknowledge())
            })??;
            assert!(workspace.cleared());
            miri_complete(selected, visited, executed, 48, stringify!($test));
            Ok(())
        }
    };
}
check!(
    scoped_parallel128_matches_and_clears,
    ParallelHash128Workspace,
    ParallelHash128
);
check!(
    scoped_parallel256_matches_and_clears,
    ParallelHash256Workspace,
    ParallelHash256
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
