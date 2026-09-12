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
