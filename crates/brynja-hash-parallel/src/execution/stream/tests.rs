use super::*;

fn config() -> StreamConfig {
    StreamConfig {
        identity: Identity::ParallelHashXof128,
        max_leaves: u128::MAX,
        workers: WorkerPolicy::Mixed,
    }
}

fn cleared(stream: &Stream<'_, '_>) {
    assert!(stream.workspace.iter().all(|byte| *byte == 0));
    assert_eq!(stream.used, [0; 16]);
    assert_eq!(stream.input_bits, [0; 16]);
    assert!(!stream.root.absorbing());
}

#[test]
fn cancellation_clears_both_input_metadata_regions_and_workspace() -> Result<(), Error> {
    let mut workspace = [0xa5; 8];
    let mut stream = Stream::new(config(), Mode::Portable, &mut workspace, &[])?;
    stream.workspace.fill(0xa5);
    stream.used = [0x5a; 16];
    stream.input_bits = [0x7f; 16];
    stream.cancel();
    cleared(&stream);
    assert!(stream.update(&[], |_| Ok(Mode::Portable)).is_err());
    cleared(&stream);
    Ok(())
}

#[test]
fn maximum_bit_count_rejects_before_callbacks_and_clears() -> Result<(), Error> {
    let mut workspace = [0; 8];
    let mut stream = Stream::new(config(), Mode::Portable, &mut workspace, &[])?;
    stream.input_bits = (u128::MAX - 7).to_le_bytes();
    stream.workspace.fill(0xa5);
    let mut calls = 0;
    assert!(matches!(
        stream.update(&[0], |_| {
            calls += 1;
            Ok(Mode::Portable)
        }),
        Err(Error::WorkLimit)
    ));
    assert_eq!(calls, 0);
    cleared(&stream);
    Ok(())
}

#[test]
fn pending_count_corruption_is_terminal_not_a_slice_panic() -> Result<(), Error> {
    let mut workspace = [0; 8];
    let mut stream = Stream::new(config(), Mode::Portable, &mut workspace, &[])?;
    stream.used = [0xff; 16];
    assert!(matches!(
        stream.update(&[0], |_| Ok(Mode::Portable)),
        Err(Error::State)
    ));
    cleared(&stream);
    Ok(())
}

#[test]
fn completion_rejects_pending_bytes_even_when_leaf_count_matches() -> Result<(), Error> {
    let mut workspace = [0; 8];
    let mut stream = Stream::new(config(), Mode::Portable, &mut workspace, &[])?;
    // Isolate the pending-byte check: the advertised empty input and root
    // count agree, but the private workspace still holds an unflushed byte.
    stream.workspace.fill(0xa5);
    stream.used = 1_u128.to_le_bytes();
    assert!(matches!(stream.check_complete(), Err(Error::State)));
    stream.cancel();
    cleared(&stream);
    Ok(())
}

#[test]
fn completion_mismatched_leaf_count_clears_all_output_paths() -> Result<(), Error> {
    for output_kind in 0..3 {
        let mut workspace = [0; 1];
        let mut configuration = config();
        if output_kind < 2 {
            configuration.identity = Identity::ParallelHash128;
        }
        let mut stream = Stream::new(configuration, Mode::Portable, &mut workspace, &[])?;
        stream.update(b"a", |_| Ok(Mode::Portable))?;
        assert_eq!(stream.merged_leaves(), 1);
        // A corrupted length advertises two leaves, not the one actually merged.
        stream.input_bits = 9_u128.to_le_bytes();
        let mut output = [0xa5; 8];
        let mut scratch = [0xa5; 8];
        match output_kind {
            0 => {
                assert!(matches!(
                    stream.finalize_secret(&mut output, |_| Ok(Mode::Portable)),
                    Err(Error::State)
                ));
                assert_eq!(output, [0; 8]);
            }
            1 => {
                assert!(matches!(
                    stream.finalize_public(
                        &mut output,
                        &mut scratch,
                        crate::ParallelHashPublicDeclassification::acknowledge(),
                        |_| Ok(Mode::Portable)
                    ),
                    Err(Error::State)
                ));
                assert_eq!(output, [0xa5; 8]);
                assert_eq!(scratch, [0; 8]);
            }
            _ => {
                assert!(matches!(
                    stream.finalize_xof(|_| Ok(Mode::Portable)),
                    Err(Error::State)
                ));
                cleared(&stream);
                assert!(stream.update(&[], |_| Ok(Mode::Portable)).is_err());
                drop(stream);
            }
        }
        assert_eq!(workspace, [0; 1]);
    }
    Ok(())
}
