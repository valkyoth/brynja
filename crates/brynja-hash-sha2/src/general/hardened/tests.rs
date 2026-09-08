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

// Fixed test inventory: the eight arrays total exactly 1170 bytes.
fn snapshot(owner: &HardenedSha2Owner) -> Result<[u8; 1170], Sha512TError> {
    let mut result = [0; 1170];
    let mut offset = 0_usize;
    for region in [
        owner.chaining_state.as_slice(),
        owner.partial_input.as_slice(),
        owner.message_length.as_slice(),
        owner.phase.as_slice(),
        owner.message_schedule.as_slice(),
        owner.block_copy.as_slice(),
        owner.padding_block.as_slice(),
        owner.output_staging.as_slice(),
    ] {
        let end = offset
            .checked_add(region.len())
            .ok_or(Sha512TError::OutputLength)?;
        result
            .get_mut(offset..end)
            .ok_or(Sha512TError::OutputLength)?
            .copy_from_slice(region);
        offset = end;
    }
    assert_eq!(offset, result.len());
    Ok(result)
}

#[test]
fn dynamic_lifecycle_rejection_retains_every_owned_byte_then_consuming_errors_clear_output()
-> Result<(), Sha512TError> {
    for t in [1, 9, 224, 256, 511] {
        let p = Sha512TBits::new(t)?;
        for invalid_width in [false, true] {
            let mut state = HardenedSha512T::new(p);
            state.update(&[0x5a; 129])?;
            state.owner.message_length = (u128::MAX / 8).to_be_bytes();
            let before = snapshot(&state.owner)?;
            assert_eq!(state.update(&[1]), Err(Sha512TError::MessageTooLong));
            assert_eq!(
                state.check_additional_bits(8),
                Err(Sha512TError::MessageTooLong)
            );
            assert_eq!(
                state.check_additional_bytes(1),
                Err(Sha512TError::MessageTooLong)
            );
            assert_eq!(snapshot(&state.owner)?, before);
            assert_eq!(state.check_additional_bits(7), Ok(()));
            state.update(&[])?;
            assert_eq!(snapshot(&state.owner)?, before);
            let mut output = [0xa5; 65];
            let length = if invalid_width { 65 } else { p.output_bytes() };
            let (destination, redzone) = output
                .split_at_mut_checked(length)
                .ok_or(Sha512TError::OutputLength)?;
            let bits = BitString::new(&[0], 8).map_err(|_| Sha512TError::MessageTooLong)?;
            let expected = if invalid_width {
                Sha512TError::OutputLength
            } else {
                Sha512TError::MessageTooLong
            };
            assert!(
                matches!(state.finalize_bits_secret(bits, destination), Err(error) if error == expected)
            );
            assert!(destination.iter().all(|byte| *byte == 0));
            assert!(redzone.iter().all(|byte| *byte == 0xa5));
        }
    }
    Ok(())
}
