extern crate std;
use super::*;

fn owner() -> Result<Core<'static>, Error> {
    Core::new(
        Mode::Portable,
        false,
        crate::execution::bits(&[0x42; 32])?,
        crate::execution::bits(b"domain")?,
        false,
    )
}

fn cleared(core: &Core<'_>) {
    assert_eq!(core.metadata.message_bytes, [0; 16]);
    assert_eq!(core.metadata.output_bits, [0; 16]);
    assert_eq!(core.metadata.phase, [0]);
    assert_eq!(core.metadata.key_class, [0]);
}

#[test]
fn every_metadata_region_is_cleared_on_cancel_and_guard_drop() -> Result<(), Error> {
    let mut core = owner()?;
    core.metadata.message_bytes = [0xa5; 16];
    core.metadata.output_bits = [0xa5; 16];
    core.metadata.phase = [0xa5];
    core.metadata.key_class = [0xa5];
    core.cancel();
    cleared(&core);
    let mut core = owner()?;
    {
        let _operation = Operation::new(&mut core);
    }
    cleared(&core);
    assert!(core.update(b"reuse").is_err());
    Ok(())
}

#[test]
fn overflow_clears_owner_and_secret_output_without_public_mutation() -> Result<(), Error> {
    let mut core = owner()?;
    core.metadata.message_bytes = u128::MAX.to_le_bytes();
    assert_eq!(core.update(b"x"), Err(Error::MessageTooLong));
    cleared(&core);
    let mut core = owner()?;
    core.finish(None, 0, true, false)?;
    core.metadata.output_bits = u128::MAX.to_le_bytes();
    let mut output = [0xa5; 1];
    let mut scratch = [0x5a; 5];
    assert_eq!(
        core.public(&mut output, 8, &mut scratch, false),
        Err(Error::OutputTooLong)
    );
    assert_eq!(output, [0xa5]);
    assert_eq!(scratch, [0; 5]);
    cleared(&core);
    let mut core = owner()?;
    core.finish(None, 0, true, false)?;
    core.metadata.output_bits = u128::MAX.to_le_bytes();
    assert!(matches!(
        core.secret(&mut output, 8, false),
        Err(Error::OutputTooLong)
    ));
    assert_eq!(output, [0]);
    cleared(&core);
    Ok(())
}

#[test]
fn invalid_tail_width_clears_all_scratch_and_terminates() -> Result<(), Error> {
    for width in [0, 9, u8::MAX] {
        let mut core = owner()?;
        core.finish(None, 0, true, false)?;
        let mut output = [0xa5; 8];
        let mut scratch = [0x5a; 9];
        assert_eq!(
            core.public(&mut output, width, &mut scratch, true),
            Err(Error::InvalidBitString)
        );
        assert_eq!(output, [0xa5; 8]);
        assert_eq!(scratch, [0; 9]);
        cleared(&core);
    }
    Ok(())
}

#[test]
fn recoverable_unwind_runs_guard_clearing() -> Result<(), Error> {
    let mut core = owner()?;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _operation = Operation::new(&mut core);
        std::panic::resume_unwind(std::boxed::Box::new(()));
    }));
    assert!(result.is_err());
    cleared(&core);
    Ok(())
}
