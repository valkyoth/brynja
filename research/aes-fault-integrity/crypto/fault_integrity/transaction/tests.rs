extern crate std;
use super::*;
use std::{
    boxed::Box,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
};

fn ack() -> PublicCiphertext {
    PublicCiphertext::acknowledge()
}

#[test]
fn successful_transactions_reuse_and_secret_owner_clears() -> Result<(), Error> {
    let mut lifecycle = Lifecycle::new();
    // All values, including zero/equal input-output, remain valid. These are
    // transaction fixtures, not an AES correctness test or echo heuristic.
    for value in 0..=255 {
        let mut output = [0x5a; 16];
        lifecycle.public(&mut output, ack(), |p, s, completion| {
            p.fill(value);
            s.fill(value);
            completion.mark_complete();
            Ok(())
        })?;
        assert_eq!(output, [value; 16]);
        assert_eq!(lifecycle.word, HEALTHY);
        let secret = lifecycle.secret(&mut output, |p, s, completion| {
            p.fill(value);
            s.fill(value);
            completion.mark_complete();
            Ok(())
        })?;
        assert_eq!(secret.expose(), &[value; 16]);
        assert_eq!(lifecycle.word, HEALTHY);
        secret.clear();
        assert_eq!(output, [0; 16]);
    }
    Ok(())
}

#[test]
fn correlated_echo_is_an_out_of_model_negative_control() -> Result<(), Error> {
    // FIPS 197 AES-128 example. Deliberately model BOTH computations being
    // skipped while their completion record is also made to look successful.
    // This is multiple correlated faults, not a detector regression or a
    // reason to reject legitimate AES fixed-point outputs.
    let plaintext = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let ciphertext = [
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5,
        0x5a,
    ];
    let mut lifecycle = Lifecycle::new();
    let mut output = [0x91; 16];
    lifecycle.public(&mut output, ack(), |primary, secondary, completion| {
        primary.copy_from_slice(&plaintext);
        secondary.copy_from_slice(&plaintext);
        completion.mark_complete();
        Ok(())
    })?;
    assert_eq!(output, plaintext); // Plaintext mislabeled public ciphertext.
    assert_ne!(output, ciphertext);

    let block = lifecycle.secret(&mut output, |primary, secondary, completion| {
        primary.copy_from_slice(&ciphertext);
        secondary.copy_from_slice(&ciphertext);
        completion.mark_complete();
        Ok(())
    })?;
    assert_eq!(block.expose(), &ciphertext); // Ciphertext mislabeled plaintext.
    assert_ne!(block.expose(), &plaintext);
    drop(block);
    assert_eq!(output, [0; 16]);
    Ok(())
}

#[test]
fn classified_rejection_is_distinct_from_later_retirement() {
    for secret in [false, true] {
        let mut lifecycle = Lifecycle::new();
        let mut output = [0x91; 16];
        let first = if secret {
            lifecycle
                .secret_profile(&mut output, |primary, secondary, _completion| {
                    primary.fill(0x42);
                    secondary.fill(0x42);
                    Ok(()) // Missing computation completion must reject.
                })
                .map(|block| block.clear())
        } else {
            lifecycle.public_profile(&mut output, ack(), |primary, secondary, _completion| {
                primary.fill(0x42);
                secondary.fill(0x42);
                Ok(())
            })
        };
        assert_eq!(first.err(), Some(ProfileFailure::RejectedAndRetired));
        assert_eq!(lifecycle.word, TERMINAL);
        assert_eq!(output, if secret { [0; 16] } else { [0x91; 16] });

        let mut invoked = false;
        output.fill(0x91);
        let later = if secret {
            lifecycle
                .secret_profile(&mut output, |_, _, _| {
                    invoked = true;
                    Ok(())
                })
                .map(|block| block.clear())
        } else {
            lifecycle.public_profile(&mut output, ack(), |_, _, _| {
                invoked = true;
                Ok(())
            })
        };
        assert_eq!(later.err(), Some(ProfileFailure::AlreadyRetired));
        assert!(!invoked);
        assert_eq!(output, if secret { [0; 16] } else { [0x91; 16] });
    }
}

#[test]
fn malformed_lifecycle_is_a_new_rejection_before_becoming_retired() {
    let mut lifecycle = Lifecycle::new();
    lifecycle.word[0] ^= 1;
    let mut output = [0x91; 16];
    let mut invoked = false;
    let first = lifecycle.public_profile(&mut output, ack(), |_, _, _| {
        invoked = true;
        Ok(())
    });
    assert_eq!(first, Err(ProfileFailure::RejectedAndRetired));
    assert_eq!(lifecycle.word, TERMINAL);
    assert_eq!(output, [0x91; 16]);
    let later = lifecycle.public_profile(&mut output, ack(), |_, _, _| {
        invoked = true;
        Ok(())
    });
    assert_eq!(later, Err(ProfileFailure::AlreadyRetired));
    assert!(!invoked);
}

#[test]
fn matching_uncomputed_results_cannot_be_released() {
    // A forged Ok from an early computation failure may leave both result
    // blocks equal, including their initial all-zero value. Equality alone
    // must not authorize either destination path.
    for value in [0u8, 0x42] {
        for secret in [false, true] {
            let mut lifecycle = Lifecycle::new();
            let mut output = [0x91; 16];
            let result = if secret {
                lifecycle
                    .secret(&mut output, |p, s, _completion| {
                        p.fill(value);
                        s.fill(value);
                        Ok(())
                    })
                    .map(|block| block.clear())
            } else {
                lifecycle.public(&mut output, ack(), |p, s, _completion| {
                    p.fill(value);
                    s.fill(value);
                    Ok(())
                })
            };
            assert!(result.is_err());
            assert_eq!(lifecycle.word, TERMINAL);
            assert_eq!(output, if secret { [0; 16] } else { [0x91; 16] });
        }
    }
}

#[test]
fn completion_record_rejects_every_single_byte_change() -> Result<(), Error> {
    let mut completion = Completion::new();
    assert!(completion.check().is_err());
    completion.mark_complete();
    completion.check()?;
    for position in 0..16 {
        for bit in 0..8 {
            let byte = completion
                .word
                .get_mut(position)
                .ok_or(Error::SecretMemory)?;
            *byte ^= 1 << bit;
            assert!(completion.check().is_err());
            *completion
                .word
                .get_mut(position)
                .ok_or(Error::SecretMemory)? ^= 1 << bit;
        }
    }
    completion.check()
}

#[test]
fn error_or_disagreement_retires_and_never_reenters_compute() {
    for error in [false, true] {
        for secret in [false, true] {
            let mut lifecycle = Lifecycle::new();
            let mut output = [0x91; 16];
            let compute = |p: &mut [u8; 16], s: &mut [u8; 16], completion: &mut Completion| {
                p.fill(1);
                s.fill(2);
                if error {
                    Err(Error::SecretMemory)
                } else {
                    completion.mark_complete();
                    Ok(())
                }
            };
            let failed = if secret {
                lifecycle.secret(&mut output, compute).is_err()
            } else {
                lifecycle.public(&mut output, ack(), compute).is_err()
            };
            assert!(failed);
            assert_eq!(lifecycle.word, TERMINAL);
            assert_eq!(output, if secret { [0; 16] } else { [0x91; 16] });
            let mut calls = 0usize;
            assert!(
                lifecycle
                    .public(&mut output, ack(), |_, _, _| {
                        calls = calls.wrapping_add(1);
                        Ok(())
                    })
                    .is_err()
            );
            assert!(
                lifecycle
                    .secret(&mut output, |_, _, _| {
                        calls = calls.wrapping_add(1);
                        Ok(())
                    })
                    .is_err()
            );
            assert_eq!(calls, 0);
            assert_eq!(output, [0; 16]);
        }
    }
}

#[test]
fn computation_unwind_retires_and_preserves_or_clears() {
    for secret in [false, true] {
        let mut lifecycle = Lifecycle::new();
        let mut output = [0x91; 16];
        let result = catch_unwind(AssertUnwindSafe(|| {
            let compute =
                |p: &mut [u8; 16], s: &mut [u8; 16], _: &mut Completion| -> Result<(), Error> {
                    p.fill(0x42);
                    s.fill(0x42);
                    resume_unwind(Box::new(()));
                };
            if secret {
                let _ = lifecycle.secret(&mut output, compute);
            } else {
                let _ = lifecycle.public(&mut output, ack(), compute);
            }
        }));
        assert!(result.is_err());
        assert_eq!(lifecycle.word, TERMINAL);
        assert_eq!(output, if secret { [0; 16] } else { [0x91; 16] });
    }
}

#[test]
fn tentative_public_write_rolls_back_on_error_and_unwind() -> Result<(), Error> {
    for unwind in [false, true] {
        let mut lifecycle = Lifecycle::new();
        let mut output = [0x91; 16];
        let result = catch_unwind(AssertUnwindSafe(|| -> Result<(), Error> {
            let mut destination = PublicTransaction::new(&mut output);
            let _operation = lifecycle.begin()?;
            destination.write(&[0x42; 16]);
            if unwind {
                resume_unwind(Box::new(()));
            }
            Err(Error::SecretMemory)
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert_eq!(result.ok(), Some(Err(Error::SecretMemory)));
        }
        assert_eq!(output, [0x91; 16]);
        assert_eq!(lifecycle.word, TERMINAL);
    }
    Ok(())
}

#[test]
fn privately_finished_secret_region_clears_on_error_and_unwind() -> Result<(), Error> {
    for unwind in [false, true] {
        let mut lifecycle = Lifecycle::new();
        let mut output = [0x91; 16];
        let result = catch_unwind(AssertUnwindSafe(|| -> Result<(), Error> {
            let mut destination = SecretRegionInitialization::begin(&mut output)?;
            let _operation = lifecycle.begin()?;
            destination.write(&[0x42; 16])?;
            let _private_region = destination.finish()?;
            if unwind {
                resume_unwind(Box::new(()));
            }
            Err(Error::SecretMemory)
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert_eq!(result.ok(), Some(Err(Error::SecretMemory)));
        }
        assert_eq!(output, [0; 16]);
        assert_eq!(lifecycle.word, TERMINAL);
    }
    Ok(())
}

#[test]
fn both_aes_engines_feed_transactions_for_all_widths_and_directions() -> Result<(), Error> {
    use crate::aes::portable;
    for width in [16, 24, 32] {
        let key = [0u8; 32];
        let key = key.get(..width).ok_or(Error::SecretMemory)?;
        for inverse in [false, true] {
            let mut output = [0x91; 16];
            let compute = |p: &mut [u8; 16], s: &mut [u8; 16], completion: &mut Completion| {
                p.fill(0x42);
                match width {
                    16 => {
                        let mut schedule = Scratch::<176>::new();
                        portable::expand(key, &mut schedule.0)?;
                        portable::transform(p, &schedule.0, inverse)?;
                    }
                    24 => {
                        let mut schedule = Scratch::<208>::new();
                        portable::wide::expand::<24, 208, 12>(key, &mut schedule.0)?;
                        portable::wide::transform::<24, 208, 12>(p, &schedule.0, inverse)?;
                    }
                    32 => {
                        let mut schedule = Scratch::<240>::new();
                        portable::wide::expand::<32, 240, 14>(key, &mut schedule.0)?;
                        portable::wide::transform::<32, 240, 14>(p, &schedule.0, inverse)?;
                    }
                    _ => return Err(Error::SecretMemory),
                }
                let mut schedule = super::super::schedule::Schedule::new();
                schedule.expand(key)?;
                schedule.transform(&[0x42; 16], s, inverse)?;
                completion.mark_complete();
                Ok(())
            };
            let block = {
                let mut lifecycle = Lifecycle::new();
                // Public release is exercised only for encryption.
                if !inverse {
                    lifecycle.public(&mut output, ack(), compute)?;
                }
                lifecycle.secret(&mut output, compute)?
            }; // Output ownership is independent of the latch.
            assert_eq!(block.expose().len(), 16);
            drop(block);
            assert_eq!(output, [0; 16]);
        }
    }
    Ok(())
}

#[test]
fn check_rejects_bad_lengths_and_non_cancelling_differences() {
    for reverse in [false, true] {
        assert!(check(&[0; 15], &[0; 16], &[0; 16], reverse).is_err());
        assert!(check(&[0; 17], &[0; 16], &[0; 16], reverse).is_err());
        // Sixteen identical differences would cancel under XOR folding.
        assert!(check(&[1; 16], &[0; 16], &[0; 16], reverse).is_err());
    }
}
