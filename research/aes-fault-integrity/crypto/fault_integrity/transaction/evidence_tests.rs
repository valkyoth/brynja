//! Source mutations only; no instruction skip, flag flip or C1/DC1 evidence.
use super::*;

#[test]
fn lifecycle_codewords_resist_every_single_byte_replacement() -> Result<(), Error> {
    for (left, right, bits) in [
        (HEALTHY, IN_PROGRESS, 64),
        (HEALTHY, TERMINAL, 64),
        (IN_PROGRESS, TERMINAL, 128),
    ] {
        let distance: u32 = left
            .iter()
            .zip(right)
            .map(|(a, b)| (*a ^ b).count_ones())
            .sum();
        assert_eq!(distance, bits);
        assert!(left.iter().zip(right).all(|(a, b)| *a != b));
    }
    for initial in [HEALTHY, IN_PROGRESS, TERMINAL, [0; 16]] {
        for position in 0..16 {
            for replacement in 0..=255 {
                let mut lifecycle = Lifecycle { word: initial };
                *lifecycle
                    .word
                    .get_mut(position)
                    .ok_or(Error::SecretMemory)? = replacement;
                let allowed = lifecycle.word == HEALTHY;
                let begun = lifecycle.begin();
                assert_eq!(begun.is_ok(), allowed);
                // Even an admitted operation must retire if not completed.
                drop(begun);
                assert_eq!(lifecycle.word, TERMINAL);
            }
        }
    }
    Ok(())
}

#[test]
fn corrupt_in_progress_state_cannot_complete_or_revive() -> Result<(), Error> {
    for position in 0..16 {
        for replacement in 0..=255 {
            let mut lifecycle = Lifecycle::new();
            let operation = lifecycle.begin()?;
            *operation
                .owner
                .word
                .get_mut(position)
                .ok_or(Error::SecretMemory)? = replacement;
            let intact = operation.owner.word == IN_PROGRESS;
            assert_eq!(operation.complete().is_ok(), intact);
            assert_eq!(lifecycle.word, if intact { HEALTHY } else { TERMINAL });
        }
    }
    Ok(())
}

#[test]
fn each_readback_check_covers_every_byte_of_both_replicas() -> Result<(), Error> {
    for reverse in [false, true] {
        for changed in 0..3 {
            for position in 0..16 {
                for mask in 1..=255 {
                    let mut destination = [0x42; 16];
                    let mut primary = destination;
                    let mut secondary = destination;
                    let bytes = match changed {
                        0 => &mut destination,
                        1 => &mut primary,
                        _ => &mut secondary,
                    };
                    *bytes.get_mut(position).ok_or(Error::SecretMemory)? ^= mask;
                    assert!(check(&destination, &primary, &secondary, reverse).is_err());
                }
            }
        }
    }
    Ok(())
}

#[test]
fn tentative_destination_corruption_rolls_back_and_retires() -> Result<(), Error> {
    for position in 0..16 {
        for mask in 1..=255 {
            let mut lifecycle = Lifecycle::new();
            let mut output = [0x91; 16];
            {
                let mut destination = PublicTransaction::new(&mut output);
                let _operation = lifecycle.begin()?;
                destination.write(&[0x42; 16]);
                *destination
                    .output
                    .get_mut(position)
                    .ok_or(Error::SecretMemory)? ^= mask;
                assert!(validate(destination.output, &[0x42; 16], &[0x42; 16]).is_err());
                // Guard unwinding on ordinary error; deliberately no commit.
            }
            assert_eq!(output, [0x91; 16]);
            assert_eq!(lifecycle.word, TERMINAL);
        }
    }
    Ok(())
}

#[test]
fn corrupted_secret_copy_is_never_returned_and_clears() -> Result<(), Error> {
    for position in 0..16 {
        for mask in 1..=255 {
            let mut lifecycle = Lifecycle::new();
            let mut output = [0x91; 16];
            {
                let mut destination = SecretRegionInitialization::begin(&mut output)?;
                let _operation = lifecycle.begin()?;
                let mut copied = [0x42; 16];
                *copied.get_mut(position).ok_or(Error::SecretMemory)? ^= mask;
                // Model a corrupted write, NOT an instruction-level injection
                // into the core copy primitive or a mutation after final check.
                destination.write(&copied)?;
                let private_region = destination.finish()?;
                assert!(validate(private_region.expose(), &[0x42; 16], &[0x42; 16]).is_err());
                // No SecretBlock is issued. Private region/operation both drop.
            }
            assert_eq!(output, [0; 16]);
            assert_eq!(lifecycle.word, TERMINAL);
        }
    }
    Ok(())
}

#[test]
fn common_mode_echo_remains_an_explicit_negative_control() -> Result<(), Error> {
    let input = [0x71; 16];
    let echo = |primary: &mut [u8; 16], secondary: &mut [u8; 16], completion: &mut Completion| {
        primary.copy_from_slice(&input);
        secondary.copy_from_slice(&input);
        completion.mark_complete();
        Ok(())
    };
    let mut lifecycle = Lifecycle::new();
    let mut output = [0x91; 16];
    lifecycle.public(&mut output, PublicCiphertext::acknowledge(), echo)?;
    assert_eq!(output, input); // Correlated skipped encryption can release input.
    let block = lifecycle.secret(&mut output, echo)?;
    assert_eq!(block.expose(), &input); // Skipped decrypt can return ciphertext.
    drop(block);
    assert_eq!(output, [0; 16]);
    assert_eq!(lifecycle.word, HEALTHY);
    // These stubs model excluded correlated skips, not AES fixed-point faults.
    // Output-value filtering must not be added to hide this model boundary.
    Ok(())
}

#[test]
fn later_readback_reloads_a_changed_destination() -> Result<(), Error> {
    for position in 0..16 {
        let mut output = [0x42; 16];
        check(&output, &[0x42; 16], &[0x42; 16], false)?;
        *output.get_mut(position).ok_or(Error::SecretMemory)? ^= 1;
        assert!(check(&output, &[0x42; 16], &[0x42; 16], true).is_err());
    }
    // This directly tests two invocations, not a machine-level injection between
    // the checks in validate or proof against load forwarding on other builds.
    Ok(())
}
