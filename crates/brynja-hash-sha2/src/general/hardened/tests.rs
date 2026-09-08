use super::*;

#[test]
fn overflow_preserves_owner_and_clears_secret_output() -> Result<(), Sha512TError> {
    let parameter = Sha512TBits::new(9)?;
    let mut state = HardenedSha512T::new(parameter);
    state.owner.message_length = (u128::MAX / 8).to_be_bytes();
    let before = state.owner.chaining_state;
    assert_eq!(state.update(&[1]), Err(Sha512TError::MessageTooLong));
    assert_eq!(state.owner.chaining_state, before);
    assert_eq!(state.owner.message_length, (u128::MAX / 8).to_be_bytes());
    assert_eq!(state.owner.phase, [0, 0]);
    let mut output = [0xa5; 2];
    let tail = BitString::new(&[0], 8).map_err(|_| Sha512TError::MessageTooLong)?;
    assert!(matches!(
        state.finalize_bits_secret(tail, &mut output),
        Err(Sha512TError::MessageTooLong)
    ));
    assert_eq!(output, [0; 2]);
    Ok(())
}

#[test]
fn general_owner_wipes_every_region() -> Result<(), Sha512TError> {
    let mut state = HardenedSha512T::new(Sha512TBits::new(511)?);
    state.update(&[0xa5; 200])?;
    state.finish(None)?;
    state.owner.wipe();
    for region in [
        state.owner.chaining_state.as_slice(),
        state.owner.partial_input.as_slice(),
        state.owner.message_length.as_slice(),
        state.owner.phase.as_slice(),
        state.owner.message_schedule.as_slice(),
        state.owner.block_copy.as_slice(),
        state.owner.padding_block.as_slice(),
        state.owner.output_staging.as_slice(),
    ] {
        assert!(region.iter().all(|byte| *byte == 0));
    }
    Ok(())
}
