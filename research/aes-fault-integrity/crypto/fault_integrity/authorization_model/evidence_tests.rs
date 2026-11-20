//! Functional mutations only. NOT exact-binary C1/DC1 fault simulation.
use super::*;

fn replace_path(candidate: &mut Candidate, reverse: bool) {
    // Deliberately stronger than changing one equality bit: replace the whole
    // selected receipt with success. Models one failed check, not a real skip.
    let (bytes, code) = if reverse {
        (&mut candidate.reverse.0, REVERSE)
    } else {
        (&mut candidate.forward.0, FORWARD)
    };
    for (byte, expected) in bytes.iter_mut().zip(code.into_iter().cycle()) {
        *byte = expected;
    }
}

#[test]
fn divergent_operands_survive_one_whole_check_bypass_in_model() -> Result<(), Error> {
    let mut cases = 0usize;
    for changed in 0..3 {
        for position in 0..16 {
            for mask in 1u8..=255 {
                for bypass_reverse in [false, true] {
                    let mut operands = [[0x42; 16]; 3];
                    *operands
                        .get_mut(changed)
                        .ok_or(Error::SecretMemory)?
                        .get_mut(position)
                        .ok_or(Error::SecretMemory)? ^= mask;
                    let mut candidate =
                        Candidate::observe(&operands[0], &operands[1], &operands[2])?;
                    replace_path(&mut candidate, bypass_reverse);
                    let mut output = [0x91; 16];
                    let mut report = 0xff;
                    fault_comparison_workbench::tentative_copy_16(
                        &mut output,
                        &operands[1],
                        &candidate.forward.0,
                        &candidate.reverse.0,
                        &mut report,
                    );
                    assert_eq!(output, [0x91; 16]);
                    assert_eq!(report, 0);
                    assert!(candidate.consume().is_err());
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, 24_480);
    Ok(())
}

#[test]
fn every_single_receipt_byte_replacement_fails_closed() -> Result<(), Error> {
    for reverse in [false, true] {
        for position in 0..BYTES {
            for replacement in 0u8..=255 {
                let mut candidate = Candidate::observe(&[0x42; 16], &[0x42; 16], &[0x42; 16])?;
                let (bytes, code) = if reverse {
                    (&mut candidate.reverse.0, REVERSE)
                } else {
                    (&mut candidate.forward.0, FORWARD)
                };
                *bytes.get_mut(position).ok_or(Error::SecretMemory)? = replacement;
                assert_eq!(
                    candidate.consume().is_ok(),
                    replacement == *code.get(position % 2).ok_or(Error::SecretMemory)?
                );
            }
        }
    }
    Ok(())
}

#[test]
fn one_byte_cannot_repair_any_single_bit_divergence_receipt() -> Result<(), Error> {
    // Smallest bit-distance bad receipt: only one operand differs by one bit.
    // Each path differs in sixteen separate bytes, so fixing one cannot pass.
    for mask in [1u8, 2, 4, 8, 16, 32, 64, 128] {
        for changed in 0..3 {
            for reverse in [false, true] {
                for position in 0..BYTES {
                    for replacement in 0u8..=255 {
                        let mut operands = [[0x42; 16]; 3];
                        operands.get_mut(changed).ok_or(Error::SecretMemory)?[0] ^= mask;
                        let mut candidate =
                            Candidate::observe(&operands[0], &operands[1], &operands[2])?;
                        let bytes = if reverse {
                            &mut candidate.reverse.0
                        } else {
                            &mut candidate.forward.0
                        };
                        *bytes.get_mut(position).ok_or(Error::SecretMemory)? = replacement;
                        assert!(candidate.inspect_forward().is_err());
                        assert!(candidate.inspect_reverse().is_err());
                    }
                }
            }
        }
    }
    Ok(())
}

#[test]
fn shared_corruption_double_bypass_and_stale_receipts_are_negative_controls() -> Result<(), Error> {
    // Entirely correlated bad data agrees. Neither a codeword nor these
    // comparisons establish AES correctness in a common-mode failure.
    Candidate::observe(&[0; 16], &[0; 16], &[0; 16])?.consume()?;
    let mut candidate = Candidate::observe(&[0; 16], &[1; 16], &[0; 16])?;
    replace_path(&mut candidate, false);
    replace_path(&mut candidate, true);
    candidate.consume()?; // Two bypasses are outside the single-bypass model.

    let mut destination = [0x42; 16];
    let stale = Candidate::observe(&destination, &destination, &destination)?;
    destination[0] ^= 1;
    stale.consume()?; // Receipts do not bind a later destination or operation.
    assert!(
        Candidate::observe(&destination, &[0x42; 16], &[0x42; 16])?
            .consume()
            .is_err()
    );
    Ok(())
}
