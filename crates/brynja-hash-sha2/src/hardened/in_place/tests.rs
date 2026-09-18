extern crate std;
use super::*;

pub(super) fn cleared(owner: &HardenedSha2Owner) -> bool {
    [
        &owner.chaining_state[..],
        &owner.partial_input,
        &owner.message_length,
        &owner.phase,
        &owner.message_schedule,
        &owner.block_copy,
        &owner.padding_block,
        &owner.output_staging,
    ]
    .into_iter()
    .all(|region| region.iter().all(|byte| *byte == 0))
}
fn authority() -> PublicDeclassification {
    PublicDeclassification::acknowledge()
}

macro_rules! campaign {
    ($name:ident, $workspace:ident, $state:ident, $width:literal, $reference:ident, $bits:ident) => {
        #[test]
        fn $name() -> Result<(), HardenedSha2Error> {
            let mut workspace = $workspace::default();
            let address = core::ptr::from_ref(&workspace.owner);
            for length in [0, 1, 7, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 255, 1024] {
                let input = std::vec![0xa6; length];
                let expected = crate::$reference(&input).map_err(|_| HardenedSha2Error::MessageTooLong)?;
                for step in [1, 7, 17, 128, 1024] {
                    let mut destination = [0xa5; $width];
                    let secret = workspace.with(|mut state| {
                        assert_eq!(core::ptr::from_ref(&*state.owner), address);
                        for part in input.chunks(step) { state.update(&[])?; state.update(part)?; }
                        assert_eq!(core::ptr::from_ref(&*state.owner), address);
                        state.finalize_secret(&mut destination)
                    })?;
                    assert!(cleared(&workspace.owner));
                    assert_eq!(secret.expose(), expected.as_ref());
                    drop(secret);
                    assert_eq!(destination, [0; $width]);
                }
                for valid in 1u8..=8 {
                    let mut input = input.clone();
                    input.push(u8::MAX << 8u8.checked_sub(valid).ok_or(HardenedSha2Error::MessageTooLong)?);
                    let bits = BitString::new(&input, valid).map_err(|_| HardenedSha2Error::MessageTooLong)?;
                    let expected = crate::$bits(bits).map_err(|_| HardenedSha2Error::MessageTooLong)?;
                    let mut output = [0xa5; $width];
                    workspace.with(|state| state.finalize_bits_public(bits, &mut output, authority()))?;
                    assert_eq!(output.as_slice(), expected.as_ref());
                    assert!(cleared(&workspace.owner));
                    let secret = workspace.with(|mut state| {
                        let (prefix, tail) = input.split_at(length / 2);
                        state.update(prefix)?;
                        state.finalize_bits_secret(BitString::new(tail, valid).map_err(|_| HardenedSha2Error::MessageTooLong)?, &mut output)
                    })?;
                    assert_eq!(secret.expose(), expected.as_ref());
                    drop(secret);
                    assert_eq!(output, [0; $width]);
                    assert!(cleared(&workspace.owner));
                }
            }
            for length in 0..=65 {
                if length == $width { continue; }
                let mut output = std::vec![0xa5; length];
                assert!(matches!(workspace.with(|state| state.finalize_secret(&mut output)), Err(HardenedSha2Error::OutputLength)));
                assert!(output.iter().all(|byte| *byte == 0));
                output.fill(0xa5);
                assert_eq!(workspace.with(|state| state.finalize_public(&mut output, authority())), Err(HardenedSha2Error::OutputLength));
                assert!(output.iter().all(|byte| *byte == 0xa5));
                assert!(cleared(&workspace.owner));
            }
            for disposition in 0..4 {
                workspace.with(|mut state| {
                    state.update(b"confidential")?;
                    match disposition {
                        0 => state.cancel(),
                        1 => drop(state),
                        2 => core::mem::forget(state),
                        _ => {
                            state.owner.message_length.fill(0xff);
                            assert_eq!(state.update(b"x"), Err(HardenedSha2Error::MessageTooLong));
                            assert!(cleared(state.owner));
                            assert_eq!(state.update(&[]), Err(HardenedSha2Error::StateConsumed));
                            core::mem::forget(state);
                        }
                    }
                    Ok::<(), HardenedSha2Error>(())
                })?;
                assert!(cleared(&workspace.owner));
            }
            for bit_tail in [false, true] {
                for failed_state in [false, true] {
                    for secret in [false, true] {
                        let mut output = [0xa5; $width];
                        let expected = if failed_state { HardenedSha2Error::StateConsumed } else { HardenedSha2Error::MessageTooLong };
                        workspace.with(|mut state| {
                            state.owner.message_length.fill(0xff);
                            if failed_state { assert!(state.update(b"x").is_err()); }
                            let bits = BitString::new(b"\x80", 1).map_err(|_| HardenedSha2Error::MessageTooLong)?;
                            if secret {
                                let result = if bit_tail { state.finalize_bits_secret(bits, &mut output) } else { state.finalize_secret(&mut output) };
                                assert!(matches!(result, Err(error) if error == expected));
                            } else {
                                let result = if bit_tail { state.finalize_bits_public(bits, &mut output, authority()) } else { state.finalize_public(&mut output, authority()) };
                                assert_eq!(result, Err(expected));
                            }
                            Ok::<(), HardenedSha2Error>(())
                        })?;
                        assert_eq!(output, if secret { [0; $width] } else { [0xa5; $width] });
                        assert!(cleared(&workspace.owner));
                    }
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
            // Exercise handle Drop without the outer scope guard hiding a defect.
            let mut state = $state { owner: &mut workspace.owner, active: true, thread_bound: PhantomData };
            state.update(b"secret")?;
            let mut output = [0; $width];
            drop(state.finalize_secret(&mut output)?);
            assert!(cleared(&workspace.owner));
            // Fresh initialization after clear must restore the exact identity's IV.
            workspace.with(|state| state.finalize_public(&mut output, authority()))?;
            assert_eq!(output.as_slice(), crate::$reference(b"").map_err(|_| HardenedSha2Error::MessageTooLong)?.as_ref());
            assert!(cleared(&workspace.owner));
            Ok(())
        }
    };
}
campaign!(sha224, Sha224Workspace, Sha224, 28, sha224, sha224_bits);
campaign!(sha256, Sha256Workspace, Sha256, 32, sha256, sha256_bits);
campaign!(sha384, Sha384Workspace, Sha384, 48, sha384, sha384_bits);
campaign!(sha512, Sha512Workspace, Sha512, 64, sha512, sha512_bits);
campaign!(
    sha512_224,
    Sha512_224Workspace,
    Sha512_224,
    28,
    sha512_224,
    sha512_224_bits
);
campaign!(
    sha512_256,
    Sha512_256Workspace,
    Sha512_256,
    32,
    sha512_256,
    sha512_256_bits
);

#[test]
fn scoped_sha2_forget_unwind_and_terminal_failure() -> Result<(), HardenedSha2Error> {
    let mut workspace = Sha256Workspace::new();
    workspace.with(|mut state| {
        state.update(b"confidential")?;
        core::mem::forget(state);
        Ok::<(), HardenedSha2Error>(())
    })?;
    assert!(cleared(&workspace.owner));
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        workspace.with(|mut state| {
            assert!(state.update(b"confidential").is_ok());
            core::mem::forget(state);
            std::panic::resume_unwind(std::boxed::Box::new(()));
        });
    }));
    assert!(unwind.is_err());
    assert!(cleared(&workspace.owner));
    let mut output = [0xa5; 32];
    workspace.with(|mut state| {
        state.owner.message_length.fill(0xff);
        assert_eq!(state.update(b"x"), Err(HardenedSha2Error::MessageTooLong));
        assert!(cleared(state.owner));
        assert_eq!(state.update(&[]), Err(HardenedSha2Error::StateConsumed));
        assert!(matches!(
            state.finalize_secret(&mut output),
            Err(HardenedSha2Error::StateConsumed)
        ));
    });
    assert_eq!(output, [0; 32]);
    assert!(cleared(&workspace.owner));
    Ok(())
}
