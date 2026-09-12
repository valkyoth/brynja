use super::*;
use crate::execution::Identity;

fn cleared(root: &Collector<'_, '_, '_>) {
    assert_eq!(root.merged, [0; 16]);
    assert_eq!(root.accelerated, [0; 16]);
    assert_eq!(root.output_bits, [0; 16]);
    assert_eq!(root.phase, [0]);
}

#[test]
fn cancel_clears_all_four_root_metadata_regions() -> Result<(), Error> {
    let plan = Plan::new(Identity::ParallelHash128, b"data", 2, 2)?;
    let mut root = Collector::new(&plan, Mode::Portable, &[])?;
    root.merged = [0xa5; 16];
    root.accelerated = [0x5a; 16];
    root.output_bits = [0x7f; 16];
    root.phase = [0xff];
    root.cancel();
    cleared(&root);
    assert!(root.execute_serial(|_| Ok(Mode::Portable)).is_err());
    cleared(&root);
    Ok(())
}

#[test]
fn failed_operation_guard_clears_preexisting_metadata() -> Result<(), Error> {
    let plan = Plan::new(Identity::ParallelHash128, b"data", 2, 2)?;
    let mut root = Collector::new(&plan, Mode::Portable, &[])?;
    root.merged = [0xa5; 16];
    root.accelerated = [0x5a; 16];
    root.output_bits = [0x7f; 16];
    assert!(root.finish(256, false).is_err());
    cleared(&root);
    Ok(())
}

#[test]
fn reader_output_overflow_clears_destination_and_closes_root() -> Result<(), Error> {
    let plan = Plan::new(Identity::ParallelHashXof256, b"data", 2, 2)?;
    let mut root = Collector::new(&plan, Mode::Portable, &[])?;
    root.execute_serial(|_| Ok(Mode::Portable))?;
    root.finish(0, true)?;
    root.output_bits = [0xff; 16];
    let mut output = [0xa5; 16];
    {
        let mut reader = Reader { root: &mut root };
        assert!(matches!(
            reader.squeeze_secret(&mut output),
            Err(Error::OutputLength)
        ));
        cleared(reader.root);
        assert_eq!(output, [0; 16]);
    }
    cleared(&root);
    Ok(())
}

#[test]
fn output_width_validation_accepts_only_canonical_shapes() {
    for length in [0, 1, 2, usize::MAX] {
        for valid in 0..=u8::MAX {
            assert_eq!(
                output_length(length, valid).is_ok(),
                if length == 0 {
                    valid == 0
                } else {
                    (1..=8).contains(&valid)
                }
            );
        }
    }
}
