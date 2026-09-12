//! Incremental execution, bit-tail boundaries and affine failure acceptance.
#![cfg(feature = "hardened-execution")]
use brynja_hash_parallel::{
    Fips202BitString, ParallelHashPublicDeclassification as Public,
    execution::{Collector, Error, Identity, Mode, Plan, Stream, StreamConfig, WorkerPolicy},
};

fn config(identity: Identity, limit: u128) -> StreamConfig {
    StreamConfig {
        identity,
        max_leaves: limit,
        workers: WorkerPolicy::Mixed,
    }
}
fn bits(input: &[u8], valid: u8) -> Result<Fips202BitString<'_>, Error> {
    Fips202BitString::new(input, valid).map_err(|_| Error::State)
}
fn xof(identity: Identity) -> bool {
    matches!(
        identity,
        Identity::ParallelHashXof128 | Identity::ParallelHashXof256
    )
}

#[test]
fn irregular_updates_and_terminal_bits_match_planned_execution() -> Result<(), Error> {
    for identity in [
        Identity::ParallelHash128,
        Identity::ParallelHash256,
        Identity::ParallelHashXof128,
        Identity::ParallelHashXof256,
    ] {
        for block in [1, 8, 17] {
            for length in [0, 1, 8, 9, 33] {
                for valid in if length == 0 {
                    &[0][..]
                } else {
                    &[1, 7, 8][..]
                } {
                    let input = [1; 33];
                    let input = input.get(..length).ok_or(Error::State)?;
                    let message = bits(input, *valid)?;
                    let custom = bits(&[3], 2)?;
                    let plan = Plan::new_bits(identity, message, block, 64)?;
                    let mut planned = Collector::new_bits(&plan, Mode::Portable, custom)?;
                    planned.execute_serial(|_| Ok(Mode::Portable))?;
                    let mut expected = [0; 173];
                    let mut scratch = [0xa5; 190];
                    if xof(identity) {
                        planned.finalize_xof()?.squeeze_final_public(
                            &mut expected,
                            5,
                            &mut scratch,
                            Public::acknowledge(),
                        )?;
                    } else {
                        planned.finalize_public_bits(
                            &mut expected,
                            5,
                            &mut scratch,
                            Public::acknowledge(),
                        )?;
                    }
                    for chunk in [1, 7, 19] {
                        let mut workspace = [0xa5; 17];
                        let workspace = workspace.get_mut(..block).ok_or(Error::State)?;
                        let mut stream = Stream::new_bits(
                            config(identity, 64),
                            Mode::Portable,
                            workspace,
                            custom,
                        )?;
                        let (prefix, tail) = if *valid == 8 || input.is_empty() {
                            (input, bits(&[], 0)?)
                        } else {
                            let (last, prefix) = input.split_last().ok_or(Error::State)?;
                            (prefix, bits(core::slice::from_ref(last), *valid)?)
                        };
                        for part in prefix.chunks(chunk) {
                            stream.update(&[], |_| Ok(Mode::Portable))?;
                            stream.update(part, |_| Ok(Mode::Portable))?;
                        }
                        assert_eq!(
                            stream.input_bits(),
                            u128::try_from(prefix.len())
                                .map_err(|_| Error::State)?
                                .checked_mul(8)
                                .ok_or(Error::State)?
                        );
                        let mut output = [0xa5; 173];
                        if xof(identity) {
                            let owned = stream
                                .finalize_xof_bits(tail, |_| Ok(Mode::Portable))?
                                .squeeze_final_secret(&mut output, 5)?;
                            assert_eq!(owned.expose(), expected);
                            drop(owned);
                            drop(stream);
                        } else {
                            let owned =
                                stream.finalize_secret_bits(tail, &mut output, 5, |_| {
                                    Ok(Mode::Portable)
                                })?;
                            assert_eq!(owned.expose(), expected);
                            drop(owned);
                        }
                        assert_eq!(output, [0; 173]);
                        assert!(workspace.iter().all(|byte| *byte == 0));
                    }
                }
            }
        }
    }
    Ok(())
}

#[test]
fn budget_rejection_happens_before_selection_and_is_terminal() -> Result<(), Error> {
    let mut workspace = [0xa5; 8];
    let mut stream = Stream::new(
        config(Identity::ParallelHash128, 1),
        Mode::Portable,
        &mut workspace,
        b"",
    )?;
    let mut calls = 0_u32;
    assert_eq!(
        stream.update(&[0; 9], |_| {
            calls = calls.saturating_add(1);
            Ok(Mode::Portable)
        }),
        Err(Error::WorkLimit)
    );
    assert_eq!(calls, 0);
    assert_eq!(stream.input_bits(), 0);
    assert!(stream.update(&[], |_| Ok(Mode::Portable)).is_err());
    let mut output = [0xa5; 32];
    assert!(
        stream
            .finalize_secret(&mut output, |_| Ok(Mode::Portable))
            .is_err()
    );
    assert_eq!(output, [0; 32]);
    assert_eq!(workspace, [0; 8]);
    Ok(())
}

#[test]
fn final_tail_failure_clears_workspace_and_secret_or_preserves_public() -> Result<(), Error> {
    for secret in [false, true] {
        let mut workspace = [0xa5; 8];
        let mut stream = Stream::new(
            config(Identity::ParallelHash128, 1),
            Mode::Portable,
            &mut workspace,
            b"",
        )?;
        stream.update(&[7; 8], |_| Ok(Mode::Portable))?;
        let mut output = [0xa5; 32];
        let mut scratch = [0xa5; 40];
        let tail = bits(&[1], 1)?;
        if secret {
            assert!(matches!(
                stream.finalize_secret_bits(tail, &mut output, 8, |_| Ok(Mode::Portable)),
                Err(Error::WorkLimit)
            ));
            assert_eq!(output, [0; 32]);
        } else {
            assert_eq!(
                stream.finalize_public_bits(
                    tail,
                    &mut output,
                    8,
                    &mut scratch,
                    Public::acknowledge(),
                    |_| Ok(Mode::Portable)
                ),
                Err(Error::WorkLimit)
            );
            assert_eq!(output, [0xa5; 32]);
            assert_eq!(scratch, [0; 40]);
        }
        assert_eq!(workspace, [0; 8]);
    }
    Ok(())
}

#[test]
fn readers_cannot_reopen_input_and_errors_clear_retained_owner() -> Result<(), Error> {
    let mut workspace = [0xa5; 8];
    let mut stream = Stream::new(
        config(Identity::ParallelHashXof128, 4),
        Mode::Portable,
        &mut workspace,
        b"",
    )?;
    stream.update(b"secret", |_| Ok(Mode::Portable))?;
    let mut reader = stream.finalize_xof(|_| Ok(Mode::Portable))?;
    let mut output = [0xa5; 40];
    let mut scratch = [0xa5; 2];
    assert!(
        reader
            .squeeze_public(&mut output, &mut scratch, Public::acknowledge())
            .is_err()
    );
    assert_eq!(scratch, [0; 2]);
    assert_eq!(output, [0xa5; 40]);
    assert!(reader.squeeze_secret(&mut output).is_err());
    assert_eq!(output, [0; 40]);
    core::mem::forget(reader);
    assert_eq!(stream.input_bits(), 0);
    assert!(stream.update(b"resume", |_| Ok(Mode::Portable)).is_err());
    drop(stream);
    assert_eq!(workspace, [0; 8]);
    let mut stream = Stream::new(
        config(Identity::ParallelHashXof128, 4),
        Mode::Portable,
        &mut workspace,
        b"",
    )?;
    core::mem::forget(stream.finalize_xof(|_| Ok(Mode::Portable))?);
    assert!(stream.update(&[], |_| Ok(Mode::Portable)).is_err());
    Ok(())
}

#[test]
fn callback_unwind_and_selection_failure_clear_partial_input() -> Result<(), Error> {
    for unwind in [false, true] {
        let mut workspace = [0xa5; 8];
        let mut stream = Stream::new(
            config(Identity::ParallelHash128, 4),
            Mode::Portable,
            &mut workspace,
            b"",
        )?;
        stream.update(b"part", |_| Ok(Mode::Portable))?;
        if unwind {
            let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = stream.update(b"more", |_| {
                    std::panic::resume_unwind(Box::new(()));
                });
            }));
            assert!(caught.is_err());
        } else {
            assert!(stream.update(b"more", |_| Ok(Mode::Require(None))).is_err());
        }
        assert_eq!(stream.input_bits(), 0);
        assert_eq!(stream.merged_leaves(), 0);
        assert!(stream.update(&[], |_| Ok(Mode::Portable)).is_err());
        drop(stream);
        assert_eq!(workspace, [0; 8]);
    }
    Ok(())
}
