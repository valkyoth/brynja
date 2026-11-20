//! Capture-source case expansion: import admission and real owner propagation.
//! Checkpoints change test codegen; none of these are emitted D3/DC1 evidence.
use super::*;
use capture::{Mutation, Stage as CaptureStage};

#[test]
fn import_both_capture_replicas_all_byte_mutations() -> Result<(), Error> {
    let mut rejected = 0usize;
    let mut unchanged = 0usize;
    for width in [16usize, 24, 32] {
        for stage in [CaptureStage::AfterFirst, CaptureStage::AfterSecond] {
            for position in 0..width {
                for mutation in capture::mutations() {
                    let input = [0x42; 32];
                    let mut first = [0x91; 34];
                    let mut second = [0x92; 34];
                    let end = width.wrapping_add(1);
                    let reset =
                        capture::inject_at(stage, capture::Action::Mutate(position, mutation));
                    let result = Keys::new_profile(
                        input.get(..width).ok_or(Error::SecretMemory)?,
                        first.get_mut(1..end).ok_or(Error::SecretMemory)?,
                        second.get_mut(1..end).ok_or(Error::SecretMemory)?,
                    );
                    assert_eq!(capture::hits(), 1);
                    drop(reset);
                    if mutation.apply(0x42) == 0x42 {
                        let keys = result.map_err(Error::from)?;
                        assert!(keys.primary.iter().all(|v| *v == 0x42));
                        assert!(keys.complemented.iter().all(|v| *v == !0x42));
                        drop(keys);
                        unchanged = unchanged.wrapping_add(1);
                    } else {
                        assert!(matches!(result, Err(ProfileFailure::ImportRejected)));
                        drop(result);
                        rejected = rejected.wrapping_add(1);
                    }
                    assert_eq!(input, [0x42; 32]);
                    assert!(
                        first
                            .get(1..end)
                            .ok_or(Error::SecretMemory)?
                            .iter()
                            .all(|v| *v == 0)
                    );
                    assert!(
                        second
                            .get(1..end)
                            .ok_or(Error::SecretMemory)?
                            .iter()
                            .all(|v| *v == 0)
                    );
                    assert_eq!(first.first(), Some(&0x91));
                    assert_eq!(second.first(), Some(&0x92));
                    assert!(
                        first
                            .get(end..)
                            .ok_or(Error::SecretMemory)?
                            .iter()
                            .all(|v| *v == 0x91)
                    );
                    assert!(
                        second
                            .get(end..)
                            .ok_or(Error::SecretMemory)?
                            .iter()
                            .all(|v| *v == 0x92)
                    );
                }
            }
        }
    }
    assert_eq!((rejected, unchanged), (137_376, 9_936));
    Ok(())
}

fn exercise_path<F>(
    stage: CaptureStage,
    position: usize,
    path: usize,
    effective: bool,
    run: &mut F,
) -> Result<(), Error>
where
    F: FnMut(usize, &mut [u8; 16]) -> Result<(), Error>,
{
    let mut output = [0x91; 16];
    run(path, &mut output)?;
    let healthy = output;
    output.fill(0x91);
    let mutation = if effective {
        Mutation::Xor(1)
    } else {
        Mutation::Replace(0x24)
    };
    let reset = capture::inject_at(stage, capture::Action::Mutate(position, mutation));
    let result = run(path, &mut output);
    assert_eq!(capture::hits(), 1);
    drop(reset);
    if effective {
        assert!(result.is_err());
        assert_eq!(output, if path == 0 { [0x91; 16] } else { [0; 16] });
        let reset = capture::inject_at(stage, capture::Action::Unwind);
        for retry in 0..3 {
            assert!(run(retry, &mut output).is_err());
        }
        assert_eq!(capture::hits(), 0);
        drop(reset);
        assert_eq!(output, [0; 16]);
    } else {
        result?;
        assert_eq!(output, healthy);
        run(path, &mut output)?;
        assert_eq!(output, healthy);
    }
    Ok(())
}

#[test]
fn input_capture_both_replicas_preserve_outputs_or_retire_every_owner_path() -> Result<(), Error> {
    let mut cases = 0usize;
    for width in [16usize, 24, 32] {
        for stage in [CaptureStage::AfterFirst, CaptureStage::AfterSecond] {
            for position in 0..16 {
                for path in 0..3 {
                    for effective in [false, true] {
                        for local in [false, true] {
                            let key = [0x42; 32];
                            let mut first = [0x91; 34];
                            let mut second = [0x92; 34];
                            let end = width.wrapping_add(1);
                            let key = key.get(..width).ok_or(Error::SecretMemory)?;
                            let a = first.get_mut(1..end).ok_or(Error::SecretMemory)?;
                            let b = second.get_mut(1..end).ok_or(Error::SecretMemory)?;
                            if local {
                                let mut owner = ephemeral::Ephemeral::new(key, a, b)?;
                                exercise_path(stage, position, path, effective, &mut |p, o| {
                                    run_ephemeral(&mut owner, p, o)
                                })?;
                            } else {
                                let mut owner = Cached::new(key, a, b)?;
                                exercise_path(stage, position, path, effective, &mut |p, o| {
                                    run(&mut owner, p, o)
                                })?;
                            }
                            assert!(
                                first
                                    .get(1..end)
                                    .ok_or(Error::SecretMemory)?
                                    .iter()
                                    .all(|v| *v == 0)
                            );
                            assert!(
                                second
                                    .get(1..end)
                                    .ok_or(Error::SecretMemory)?
                                    .iter()
                                    .all(|v| *v == 0)
                            );
                            assert_eq!(first.first(), Some(&0x91));
                            assert_eq!(second.first(), Some(&0x92));
                            assert!(
                                first
                                    .get(end..)
                                    .ok_or(Error::SecretMemory)?
                                    .iter()
                                    .all(|v| *v == 0x91)
                            );
                            assert!(
                                second
                                    .get(end..)
                                    .ok_or(Error::SecretMemory)?
                                    .iter()
                                    .all(|v| *v == 0x92)
                            );
                            cases = cases.wrapping_add(1);
                        }
                    }
                }
            }
        }
    }
    // Three widths * two copies * 16 bytes * three paths * two outcomes * two owners.
    assert_eq!(cases, 1_152);
    Ok(())
}
