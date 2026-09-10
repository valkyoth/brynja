extern crate std;
use super::*;

fn cleared(owner: &HardenedSha2Owner) -> bool {
    owner
        .chaining_state
        .iter()
        .chain(&owner.partial_input)
        .chain(&owner.message_length)
        .chain(&owner.phase)
        .chain(&owner.message_schedule)
        .chain(&owner.block_copy)
        .chain(&owner.padding_block)
        .chain(&owner.output_staging)
        .all(|byte| *byte == 0)
}

#[test]
fn failed_and_unwinding_update_clears_all_eight_regions() {
    let mut owner = HardenedSha2Owner::new64([1; 8]);
    let mut failed = false;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let guard = Update {
            owner: &mut owner,
            failed: &mut failed,
            completed: false,
        };
        guard.owner.partial_input.fill(1);
        guard.owner.message_length.fill(1);
        guard.owner.phase.fill(1);
        guard.owner.message_schedule.fill(1);
        guard.owner.block_copy.fill(1);
        guard.owner.padding_block.fill(1);
        guard.owner.output_staging.fill(1);
        std::panic::resume_unwind(std::boxed::Box::new("update cleanup probe"));
    }));
    assert!(result.is_err());
    assert!(failed);
    assert!(cleared(&owner));
}

#[test]
fn synthetic_length_and_work_exhaustion_reject_before_mutation() -> Result<(), Error> {
    for wide in [false, true] {
        let mut engine = Engine::new(
            HardenedSha2Owner::new64([0; 8]),
            Execution::portable(),
            wide,
            false,
        )?;
        if wide {
            engine.owner.message_length = (u128::MAX / 8).to_be_bytes();
        } else {
            engine.owner.message_length[..8].copy_from_slice(&(u64::MAX / 8).to_be_bytes());
        }
        engine.owner.set_buffer_len(if wide { 127 } else { 63 });
        let before = engine.owner.message_length;
        assert_eq!(engine.update(&[0]), Err(Error::MessageTooLong));
        assert_eq!(engine.owner.message_length, before);
        assert!(!engine.failed);
        assert!(engine.check_bits(7).is_ok());
        assert_eq!(engine.check_bits(8), Err(Error::MessageTooLong));
        engine.owner.message_length.fill(0);
        engine.report.message_blocks = u128::MAX;
        assert_eq!(engine.update(&[0]), Err(Error::MessageTooLong));
        assert!(!engine.failed);
        assert_eq!(engine.report.message_blocks, u128::MAX);
    }
    Ok(())
}
