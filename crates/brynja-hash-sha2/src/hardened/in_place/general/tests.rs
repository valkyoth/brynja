extern crate std;
use super::*;
use crate::hardened::in_place::tests::cleared;

fn authority() -> PublicDeclassification {
    PublicDeclassification::acknowledge()
}

#[test]
fn every_parameter_binds_canonical_secret_and_public_output() -> Result<(), Sha512TError> {
    for t in 1..512 {
        if t == 384 {
            continue;
        }
        let parameter = Sha512TBits::new(t)?;
        let mut workspace = Sha512TWorkspace::new(parameter);
        assert_eq!(workspace.parameter(), parameter);
        let address = core::ptr::from_ref(&workspace.owner);
        for length in [0, 1, 111, 112, 127, 128, 129, 255, 1024] {
            let input = std::vec![0xa6; length];
            let expected = crate::sha512_t(parameter, &input)?;
            let mut destination = std::vec![0xa5; parameter.output_bytes()];
            let secret = workspace.with(|mut state| {
                assert_eq!(state.parameter(), parameter);
                assert_eq!(core::ptr::from_ref(&*state.owner), address);
                for part in input.chunks(17) {
                    state.update(&[])?;
                    state.update(part)?;
                }
                state.finalize_secret(&mut destination)
            })?;
            assert!(cleared(&workspace.owner));
            assert_eq!(secret.parameter(), parameter);
            assert_eq!(secret.as_bytes(), expected.as_bytes());
            assert_eq!(
                secret.as_bytes().last().copied().unwrap_or_default() & !parameter.last_byte_mask(),
                0
            );
            assert_eq!(secret.declassify(authority())?, expected);
            assert!(destination.iter().all(|byte| *byte == 0));
            assert_eq!(
                workspace.with(|mut state| {
                    state.update(&input)?;
                    state.finalize_public(authority())
                })?,
                expected
            );
            assert!(cleared(&workspace.owner));
        }
        for valid in 1u8..=8 {
            let mut input = [0xa6; 130];
            *input.last_mut().ok_or(Sha512TError::MessageTooLong)? =
                u8::MAX << 8u8.checked_sub(valid).ok_or(Sha512TError::MessageTooLong)?;
            let bits = BitString::new(&input, valid).map_err(|_| Sha512TError::MessageTooLong)?;
            let expected = crate::sha512_t_bits(parameter, bits)?;
            let mut output = std::vec![0xa5; parameter.output_bytes()];
            let secret = workspace.with(|mut state| {
                let (prefix, tail) = input.split_at(63);
                state.update(prefix)?;
                state.finalize_bits_secret(
                    BitString::new(tail, valid).map_err(|_| Sha512TError::MessageTooLong)?,
                    &mut output,
                )
            })?;
            assert_eq!(secret.as_bytes(), expected.as_bytes());
            assert_eq!(secret.parameter(), parameter);
            drop(secret);
            assert!(output.iter().all(|byte| *byte == 0));
            assert!(cleared(&workspace.owner));
            assert_eq!(
                workspace.with(|state| state.finalize_bits_public(bits, authority()))?,
                expected
            );
            assert!(cleared(&workspace.owner));
        }
        for width in 0..=65 {
            if width == parameter.output_bytes() {
                continue;
            }
            let mut output = std::vec![0xa5; width];
            let result = workspace.with(|mut state| {
                state.update(b"secret")?;
                state.finalize_secret(&mut output)
            });
            assert!(matches!(result, Err(Sha512TError::OutputLength)));
            drop(result);
            assert!(output.iter().all(|byte| *byte == 0));
            assert!(cleared(&workspace.owner));
        }
    }
    Ok(())
}

#[test]
fn scoped_general_forget_unwind_and_terminal_failure() -> Result<(), Sha512TError> {
    let parameter = Sha512TBits::new(9)?;
    let mut workspace = Sha512TWorkspace::new(parameter);
    for disposition in 0..4 {
        workspace.with(|mut state| {
            state.update(b"confidential")?;
            match disposition {
                0 => state.cancel(),
                1 => drop(state),
                2 => core::mem::forget(state),
                _ => {
                    state.owner.message_length.fill(0xff);
                    assert_eq!(state.update(b"x"), Err(Sha512TError::MessageTooLong));
                    assert!(cleared(state.owner));
                    assert_eq!(state.update(&[]), Err(Sha512TError::StateConsumed));
                    core::mem::forget(state);
                }
            }
            Ok::<(), Sha512TError>(())
        })?;
        assert!(cleared(&workspace.owner));
    }
    for bit_tail in [false, true] {
        for failed in [false, true] {
            let mut output = [0xa5; 2];
            workspace.with(|mut state| {
                state.owner.message_length.fill(0xff);
                if failed {
                    assert!(state.update(b"x").is_err());
                }
                let tail = BitString::new(b"\x80", 1).map_err(|_| Sha512TError::MessageTooLong)?;
                let result = if bit_tail {
                    state.finalize_bits_secret(tail, &mut output)
                } else {
                    state.finalize_secret(&mut output)
                };
                let expected = if failed {
                    Sha512TError::StateConsumed
                } else {
                    Sha512TError::MessageTooLong
                };
                assert!(matches!(result, Err(error) if error == expected));
                Ok::<(), Sha512TError>(())
            })?;
            assert_eq!(output, [0; 2]);
            assert!(cleared(&workspace.owner));
        }
    }
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        workspace.with(|mut state| {
            assert!(state.update(b"confidential").is_ok());
            core::mem::forget(state);
            std::panic::resume_unwind(std::boxed::Box::new(()));
        });
    }));
    assert!(unwind.is_err());
    assert!(cleared(&workspace.owner));
    // Bypass the outer guard to make the handle destructor independently testable.
    let mut state = Sha512T {
        owner: &mut workspace.owner,
        parameter,
        active: true,
        thread_bound: PhantomData,
    };
    state.update(b"secret")?;
    state.cancel();
    assert!(cleared(&workspace.owner));
    assert_eq!(
        workspace.with(|state| state.finalize_public(authority()))?,
        crate::sha512_t(parameter, b"")?
    );
    assert!(cleared(&workspace.owner));
    Ok(())
}
