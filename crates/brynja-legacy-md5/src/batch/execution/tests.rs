use super::*;

#[test]
fn eligibility_distinguishes_inactive_empty_and_partial_blocks() -> Result<(), crate::BitStringError>
{
    let data = [0u8; 64];
    let complete = BitString::new(&data, 8)?;
    let partial = BitString::new(&data, 7)?;
    let empty = BitString::new(&[], 0)?;
    let mut inputs = [Some(complete); 8];
    assert!(eligible(&inputs, 8));
    if let Some(first) = inputs.first_mut() {
        *first = Some(partial);
    }
    assert!(!eligible(&inputs, 8));
    assert!(eligible(&inputs, 4));
    if let Some(slot) = inputs.get_mut(4) {
        *slot = Some(empty);
    }
    assert!(!eligible(&inputs, 4));
    if let Some(slot) = inputs.get_mut(4) {
        *slot = None;
    }
    assert!(!eligible(&inputs, 4));
    Ok(())
}

#[test]
fn cancellation_budget_and_final_callback_revocation_preserve_output()
-> Result<(), crate::BitStringError> {
    let data = [0u8; 64];
    let inputs = [Some(BitString::new(&data, 8)?); 8];
    let owner = Executor::portable();
    let mut output = [[0xa5; 16]; 8];
    let mut control = Md5BatchControl::new(0);
    assert_eq!(
        owner.digest(
            &inputs,
            &mut output,
            &mut control,
            PublicData::acknowledge()
        ),
        Err(Error::Batch(Md5BatchError::WorkLimit))
    );
    assert_eq!(output, [[0xa5; 16]; 8]);
    // The all-inactive portable operation calls the observer before and after work.
    let mut calls = 0;
    let mut revoke = || {
        calls += 1;
        if calls == 2 {
            owner.quarantine();
        }
        false
    };
    let mut control = Md5BatchControl::with_cancellation(0, &mut revoke);
    assert_eq!(
        owner.digest(
            &[None; 8],
            &mut output,
            &mut control,
            PublicData::acknowledge()
        ),
        Err(Error::Quarantined)
    );
    assert_eq!(output, [[0xa5; 16]; 8]);
    Ok(())
}

#[test]
fn required_workload_rejection_needs_no_work_or_output_mutation() {
    // An interpreter-only malformed authority-free owner cannot execute SIMD.
    let owner = Executor {
        authority: None,
        required: true,
        revoked: Cell::new(false),
    };
    let mut output = [[0xa5; 16]; 8];
    let mut calls = 0;
    let mut cancelled = || {
        calls += 1;
        true
    };
    let mut control = Md5BatchControl::with_cancellation(999, &mut cancelled);
    assert_eq!(
        owner.digest(
            &[None; 8],
            &mut output,
            &mut control,
            PublicData::acknowledge()
        ),
        Err(Error::IneligibleWorkload)
    );
    assert_eq!(output, [[0xa5; 16]; 8]);
    assert_eq!(control.remaining(), 999);
    assert_eq!(calls, 0);
}
