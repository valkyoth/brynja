use super::*;

macro_rules! check {
    ($test:ident, $workspace:ident, $ordinary:ident) => {
        #[test]
        fn $test() -> Result<(), Box<dyn std::error::Error>> {
            let Some(root) = owner()? else {
                return Ok(());
            };
            let Some(leaf) = owner()? else {
                return Ok(());
            };
            let run = || -> Result<(), Error> {
                let mut workspace = api::$workspace::new(session(&root)?, session(&leaf)?)?;
                for b in [1, 7, 8, 136, 168] {
                    for valid in 1..=8 {
                        let mut storage = [0xa5; 168];
                        let block = storage.get_mut(..b).ok_or(Error::StateConsumed)?;
                        let input = [0x35; 173];
                        let tail = Fips202BitString::new(&[1], valid)
                            .map_err(|_| Error::InvalidBitString)?;
                        let custom =
                            Fips202BitString::new(&[3], 2).map_err(|_| Error::InvalidBitString)?;
                        let mut reference_storage = [0; 168];
                        let mut reference = hash::$ordinary::new_bits(
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
                        let mut scratch = [0xa5; 511];
                        let last = workspace.with_bits_and_scratch(
                            block,
                            custom,
                            &mut scratch,
                            |mut state| {
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
                            },
                        )??;
                        assert_eq!(
                            last.expose(),
                            expected.get(337..).ok_or(Error::StateConsumed)?
                        );
                        assert!(block.iter().all(|byte| *byte == 0));
                        drop(last);
                        assert_eq!(final_output, [0; 174]);
                        assert_eq!(root.report().health, Health::Healthy);
                        let mut public = [0xa5; 511];
                        workspace.with_bits_and_scratch(
                            block,
                            custom,
                            &mut scratch,
                            |mut state| {
                                state.update(&input)?;
                                state.finalize_bits_xof(tail)?.squeeze_final_bits_public(
                                    &mut public,
                                    valid,
                                    Public::acknowledge(),
                                )
                            },
                        )??;
                        assert_eq!(public, expected);
                        assert_eq!(scratch, [0; 511]);
                    }
                }
                let mut block = [0xa5; 8];
                for action in 0..3 {
                    workspace.with(&mut block, b"", |mut state| {
                        state.update(b"pending")?;
                        if action == 0 {
                            state.cancel();
                        } else {
                            let mut reader = state.finalize_xof()?;
                            reader.squeeze_public(&mut [0; 168], Public::acknowledge())?;
                            if action == 1 {
                                reader.cancel();
                            } else {
                                core::mem::forget(reader);
                            }
                        }
                        Ok::<(), Error>(())
                    })??;
                    assert_eq!(block, [0; 8]);
                    assert_eq!(root.report().health, Health::Healthy);
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
                    assert_eq!(root.report().health, Health::Healthy);
                }
                let mut entered = false;
                assert!(workspace.with(&mut [], b"", |_| entered = true).is_err());
                assert!(!entered);
                workspace.with(&mut block, b"", |state| {
                    state.finalize_xof()?.squeeze_final_bits_public(
                        &mut [],
                        0,
                        Public::acknowledge(),
                    )
                })??;
                drop(workspace.with(&mut block, b"", |state| {
                    state.finalize_xof()?.squeeze_final_bits_secret(&mut [], 0)
                })??);
                Ok(())
            };
            run().map_err(|e| format!("scoped accelerated XOF: {e:?}"))?;
            println!("SCOPED_PARALLELHASH_XOF: {}", stringify!($workspace));
            Ok(())
        }
    };
}
check!(
    scoped_accelerated_parallel_xof128_matches_and_clears,
    ParallelHashXof128Workspace,
    ParallelHashXof128
);
check!(
    scoped_accelerated_parallel_xof256_matches_and_clears,
    ParallelHashXof256Workspace,
    ParallelHashXof256
);
