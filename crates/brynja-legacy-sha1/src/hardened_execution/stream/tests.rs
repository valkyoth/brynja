use super::*;
extern crate std;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn cleared(owner: &Sha1Owner) {
    assert_eq!(owner.chaining_state, [0; 20]);
    assert_eq!(owner.block, [0; 64]);
    assert_eq!(owner.schedule, [0; 320]);
    assert_eq!(owner.message_length, [0; 8]);
    assert_eq!(owner.buffered, [0]);
    assert_eq!(owner.output_staging, [0; 20]);
}

#[test]
fn invariant_failure_clears_all_owned_regions_and_quarantines() -> Result<(), Error> {
    let executor = Executor::portable();
    let mut stream = executor.start()?;
    stream.owner.block.fill(0xa5);
    stream.owner.schedule.fill(0xa5);
    stream.owner.output_staging.fill(0xa5);
    stream.owner.buffered = [64];
    assert!(stream.update(&[1]).is_err());
    cleared(&stream.owner);
    assert!(stream.failed);
    assert!(executor.start().is_err());
    Ok(())
}

#[test]
fn update_guard_clears_during_recoverable_unwind() -> Result<(), Error> {
    let executor = Executor::portable();
    let mut stream = executor.start()?;
    stream.update(b"secret")?;
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let _operation = Operation {
                state: &mut stream,
                completed: false,
            };
            std::panic::resume_unwind(std::boxed::Box::new("test-only interruption"));
        }))
        .is_err()
    );
    cleared(&stream.owner);
    assert!(stream.failed);
    assert!(executor.start().is_err());
    Ok(())
}

#[test]
fn length_rejection_is_atomic_and_does_not_revoke_siblings() -> Result<(), Error> {
    let executor = Executor::portable();
    let mut stream = executor.start()?;
    stream.update(b"x")?;
    stream.owner.message_length = (u64::MAX - 7).to_be_bytes();
    let before = stream.owner.block;
    assert_eq!(stream.update(b"x"), Err(Sha1Error::MessageTooLong.into()));
    assert_eq!(stream.owner.block, before);
    assert_eq!(stream.owner.bits(), u64::MAX - 7);
    let tail = BitString::new(b"x", 8).map_err(|_| Sha1Error::MessageTooLong)?;
    let mut destination = [0xa5; 20];
    assert!(stream.finalize_bits_secret(tail, &mut destination).is_err());
    assert_eq!(destination, [0; 20]);
    assert!(executor.start().is_ok());
    Ok(())
}

#[test]
fn internal_bit_admission_retains_exact_domain_and_output_contracts() -> Result<(), Error> {
    let executor = Executor::portable();
    for current in [0, 1, 7, 8, 63, 64, 1024, u64::MAX - 7, u64::MAX] {
        let mut stream = executor.start()?;
        stream.owner.message_length = current.to_be_bytes();
        // Only private admission may query synthetic widths. Real public
        // operations still reject exhausted message domains before mutation.
        assert!(crate::engine::admit_bits(stream.owner.bits(), u64::MAX - current).is_ok());
        if current > 0 {
            assert!(
                crate::engine::admit_bits(stream.owner.bits(), u64::MAX - current + 1).is_err()
            );
        }
    }
    for secret in [false, true] {
        let mut stream = executor.start()?;
        stream.owner.message_length = u64::MAX.to_be_bytes();
        let tail = BitString::new(&[0x80], 1).map_err(|_| Sha1Error::MessageTooLong)?;
        let mut destination = [0xa5; 20];
        if secret {
            assert!(stream.finalize_bits_secret(tail, &mut destination).is_err());
            assert_eq!(destination, [0; 20]);
        } else {
            assert_eq!(
                stream.finalize_bits_public(
                    tail,
                    &mut destination,
                    PublicDeclassification::acknowledge()
                ),
                Err(Sha1Error::MessageTooLong.into())
            );
            assert_eq!(destination, [0xa5; 20]);
        }
    }
    assert!(executor.start().is_ok());
    Ok(())
}
