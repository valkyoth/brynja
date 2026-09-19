use super::*;
use crate::{
    Fips202BitString, Fips202Output, ParallelHashError as Error,
    ParallelHashPublicDeclassification as Public,
};

macro_rules! check {
    ($test:ident, $workspace:ident, $ordinary:ident) => {
        #[test]
        fn $test() -> Result<(), Error> {
            let mut workspace = $workspace::new();
            for b in [1, 7, 8, 17, 136, 168] {
                let mut storage = [0xa5; 168];
                let block = storage.get_mut(..b).ok_or(Error::StateConsumed)?;
                let input = [0x05; 177];
                for bits in 1..=8 {
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
