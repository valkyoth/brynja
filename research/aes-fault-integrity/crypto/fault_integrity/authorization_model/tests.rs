use super::*;

#[test]
fn equal_inputs_have_distinct_nonzero_full_receipts() -> Result<(), Error> {
    for value in 0u8..=255 {
        let data = [value; 16];
        let candidate = Candidate::observe(&data, &data, &data)?;
        for pair in candidate.forward.0.as_chunks::<2>().0 {
            assert_eq!(*pair, FORWARD);
        }
        for pair in candidate.reverse.0.as_chunks::<2>().0 {
            assert_eq!(*pair, REVERSE);
        }
        assert!(candidate.forward.0.iter().all(|b| *b != 0));
        assert!(candidate.reverse.0.iter().all(|b| *b != 0));
        assert!(
            candidate
                .forward
                .0
                .iter()
                .zip(candidate.reverse.0.iter())
                .all(|(a, b)| *a == !b)
        );
        let mut tentative = Scratch::<16>::new();
        let mut report = Scratch::<1>::new();
        fault_comparison_workbench::tentative_copy_16(
            &mut tentative.0,
            &data,
            &candidate.forward.0,
            &candidate.reverse.0,
            &mut report.0[0],
        );
        assert_eq!(tentative.0, data);
        assert_eq!(report.0, [0xa5]);
        candidate.consume()?;
    }
    Ok(())
}

#[test]
fn fresh_permit_requires_actual_destination_to_match_both_results() -> Result<(), Error> {
    let denied = [0xc3; 16];
    let permitted = [0x3c; 16];
    for value in 0u8..=255 {
        let expected = [value; 16];
        let mut state = [0x11; 16];
        permit_fresh(
            &expected, &expected, &expected, &mut state, &denied, &permitted,
        )?;
        assert_eq!(state, permitted);

        for changed in 0..3 {
            for position in 0..16 {
                let mut operands = [expected; 3];
                *operands
                    .get_mut(changed)
                    .ok_or(Error::SecretMemory)?
                    .get_mut(position)
                    .ok_or(Error::SecretMemory)? ^= 1;
                state.fill(0x11);
                assert!(
                    permit_fresh(
                        &operands[0],
                        &operands[1],
                        &operands[2],
                        &mut state,
                        &denied,
                        &permitted,
                    )
                    .is_err()
                );
                assert_eq!(state, denied);
            }
        }
    }
    let mut state = [0x11; 16];
    assert!(
        permit_fresh(
            &[0; 15], &[0; 16], &[0; 16], &mut state, &denied, &permitted
        )
        .is_err()
    );
    assert_eq!(state, denied);
    Ok(())
}

#[test]
fn every_operand_byte_difference_changes_every_lane() -> Result<(), Error> {
    for changed in 0..3 {
        for position in 0..16 {
            for mask in 1u8..=255 {
                let mut operands = [[0x42; 16]; 3];
                *operands
                    .get_mut(changed)
                    .ok_or(Error::SecretMemory)?
                    .get_mut(position)
                    .ok_or(Error::SecretMemory)? ^= mask;
                let candidate = Candidate::observe(&operands[0], &operands[1], &operands[2])?;
                let expected = match changed {
                    0 => [mask, mask],
                    1 => [mask, 0],
                    _ => [0, mask],
                };
                for pair in candidate.forward.0.as_chunks::<2>().0 {
                    assert_eq!(*pair, [FORWARD[0] ^ expected[0], FORWARD[1] ^ expected[1]]);
                }
                for pair in candidate.reverse.0.as_chunks::<2>().0 {
                    assert_eq!(*pair, [REVERSE[0] ^ expected[0], REVERSE[1] ^ expected[1]]);
                }
                // Stable mismatch is encoded in at least sixteen distinct
                // bytes of EACH path, not one byte padded with fixed constants.
                for (bytes, code) in [
                    (&candidate.forward.0, FORWARD),
                    (&candidate.reverse.0, REVERSE),
                ] {
                    let byte_distance = bytes
                        .iter()
                        .zip(code.into_iter().cycle())
                        .filter(|(actual, expected)| **actual != *expected)
                        .count();
                    let bit_distance: u32 = bytes
                        .iter()
                        .zip(code.into_iter().cycle())
                        .map(|(actual, expected)| (*actual ^ expected).count_ones())
                        .sum();
                    assert!(byte_distance >= LANES);
                    assert!(bit_distance >= 16);
                }
                assert!(candidate.inspect_forward().is_err());
                assert!(candidate.inspect_reverse().is_err());
                assert!(candidate.consume().is_err());
            }
        }
    }
    Ok(())
}

#[test]
fn mixed_equal_differences_do_not_cancel() -> Result<(), Error> {
    for seed in 0u8..=255 {
        let mut destination = [0; 16];
        for (offset, byte) in (0u8..16).zip(destination.iter_mut()) {
            *byte = seed.wrapping_add(offset);
        }
        let mut primary = destination;
        let mut secondary = destination;
        primary[0] ^= 0x81;
        primary[15] ^= 0x81;
        secondary[7] ^= 0x42;
        secondary[8] ^= 0x42;
        let candidate = Candidate::observe(&destination, &primary, &secondary)?;
        assert!(candidate.inspect_forward().is_err());
        assert!(candidate.inspect_reverse().is_err());
        assert!(candidate.consume().is_err());
    }
    Ok(())
}

#[test]
fn zero_initialization_and_each_partial_receipt_fail() {
    for count in 0..BYTES {
        let mut partial = Candidate {
            forward: Scratch::new(),
            reverse: Scratch::new(),
        };
        for (byte, code) in partial
            .forward
            .0
            .iter_mut()
            .take(count)
            .zip(FORWARD.into_iter().cycle())
        {
            *byte = code;
        }
        for (byte, code) in partial
            .reverse
            .0
            .iter_mut()
            .take(count)
            .zip(REVERSE.into_iter().cycle())
        {
            *byte = code;
        }
        assert!(partial.inspect_forward().is_err());
        assert!(partial.inspect_reverse().is_err());
        assert!(partial.consume().is_err());
    }
}

#[test]
fn exchanging_forward_and_reverse_receipts_is_not_success() -> Result<(), Error> {
    let mut candidate = Candidate::observe(&[0; 16], &[0; 16], &[0; 16])?;
    core::mem::swap(&mut candidate.forward, &mut candidate.reverse);
    assert!(candidate.inspect_forward().is_err());
    assert!(candidate.inspect_reverse().is_err());
    assert!(candidate.consume().is_err());
    Ok(())
}
