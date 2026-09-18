extern crate std;
use super::*;

fn cleared<const RATE: usize>(owner: &HardenedFips202Owner<RATE>) -> bool {
    [
        &owner.sponge_lanes[..],
        &owner.partial_input,
        &owner.message_length,
        &owner.output_length,
        &owner.cshake_setup_length,
        &owner.cshake_domain,
        &owner.phase,
        &owner.suffix_staging,
        &owner.padding_block,
        &owner.squeeze_staging,
        &owner.permutation_columns,
        &owner.permutation_theta,
        &owner.permutation_rearranged,
    ]
    .into_iter()
    .all(|region| region.iter().all(|byte| *byte == 0))
}

macro_rules! campaign {
    ($name:ident, $workspace:ident, $state:ident, $width:expr, $reference:ident, $bits:ident) => {
        #[test]
        fn $name() -> Result<(), HardenedSha3Error> {
            let mut workspace = $workspace::new();
            let address = core::ptr::from_ref(&workspace.owner);
            for length in [0, 1, 7, 8, 71, 72, 103, 104, 135, 136, 143, 144, 167, 168, 169, 335, 1024] {
                let input = std::vec![0x5a; length];
                let expected = crate::$reference(&input).map_err(|_| HardenedSha3Error::MessageTooLong)?;
                for step in [1, 7, 17, 168, 1024] {
                    let mut destination = [0xa5; $width];
                    let secret = workspace.with(|mut state| {
                        assert_eq!(core::ptr::from_ref(&*state.owner), address);
                        for part in input.chunks(step) {
                            state.update(&[])?;
                            state.update(part)?;
                            assert_eq!(core::ptr::from_ref(&*state.owner), address);
                        }
                        state.finalize_secret(&mut destination)
                    })?;
                    assert!(cleared(&workspace.owner));
                    assert_eq!(secret.expose(), expected.as_bytes());
                    drop(secret);
                    assert_eq!(destination, [0; $width]);
                }
                for valid in 1u8..=7 {
                    let mut full = input.clone();
                    full.push((1u8 << valid).checked_sub(1).ok_or(HardenedSha3Error::MessageTooLong)?);
                    let bits = Fips202BitString::new(&full, valid).map_err(|_| HardenedSha3Error::MessageTooLong)?;
                    let expected = crate::$bits(bits).map_err(|_| HardenedSha3Error::MessageTooLong)?;
                    let mut destination = [0xa5; $width];
                    // Complete-byte and partial-bit tails share the same API.
                    workspace.with(|state| state.finalize_bits_public(bits, &mut destination, Sha3PublicDeclassification::acknowledge()))?;
                    assert_eq!(&destination, expected.as_bytes());
                    assert!(cleared(&workspace.owner));
                    let secret = workspace.with(|mut state| {
                        let (prefix, tail) = full.split_at(length.checked_div(2).unwrap_or_default());
                        state.update(prefix)?;
                        let tail = Fips202BitString::new(tail, valid).map_err(|_| HardenedSha3Error::MessageTooLong)?;
                        state.finalize_bits_secret(tail, &mut destination)
                    })?;
                    assert_eq!(secret.expose(), expected.as_bytes());
                    drop(secret);
                    assert_eq!(destination, [0; $width]);
                    assert!(cleared(&workspace.owner));
                }
            }
            for width in 0..=65 {
                if width == $width { continue; }
                let mut secret = std::vec![0xa5; width];
                let result = workspace.with(|mut state| {
                    state.update(b"secret")?;
                    state.finalize_secret(&mut secret)
                });
                assert!(matches!(result, Err(HardenedSha3Error::OutputLength)));
                drop(result);
                assert!(secret.iter().all(|byte| *byte == 0));
                assert!(cleared(&workspace.owner));
                let mut public = std::vec![0xa5; width];
                assert_eq!(workspace.with(|state| state.finalize_public(&mut public, Sha3PublicDeclassification::acknowledge())), Err(HardenedSha3Error::OutputLength));
                assert!(public.iter().all(|byte| *byte == 0xa5));
                assert!(cleared(&workspace.owner));
            }
            for disposition in 0..4 {
                workspace.with(|mut state| {
                    state.update(b"secret")?;
                    match disposition {
                        0 => state.cancel(),
                        1 => drop(state),
                        2 => core::mem::forget(state),
                        _ => {
                            state.owner.message_length.fill(0xff);
                            assert_eq!(state.update(b"x"), Err(HardenedSha3Error::MessageTooLong));
                            assert!(cleared(state.owner));
                            assert_eq!(state.update(&[]), Err(HardenedSha3Error::StateConsumed));
                            core::mem::forget(state);
                        }
                    }
                    Ok::<(), HardenedSha3Error>(())
                })?;
                assert!(cleared(&workspace.owner));
            }
            // Exercise the handle destructor without the outer guard masking it.
            let mut destination = [0; $width];
            let mut state = $state { owner: &mut workspace.owner, active: true, thread_bound: PhantomData };
            state.update(b"secret")?;
            let secret = state.finalize_secret(&mut destination)?;
            assert!(cleared(&workspace.owner));
            drop(secret);
            // Error-state finalization must still clear a valid-sized destination.
            destination.fill(0xa5);
            let result = workspace.with(|mut state| {
                state.owner.message_length.fill(0xff);
                assert!(state.update(b"x").is_err());
                state.finalize_secret(&mut destination)
            });
            assert!(matches!(result, Err(HardenedSha3Error::StateConsumed)));
            drop(result);
            assert_eq!(destination, [0; $width]);
            // Forgetting the state before an unwind cannot bypass the scope guard.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                workspace.with(|mut state| {
                    assert!(state.update(b"secret").is_ok());
                    core::mem::forget(state);
                    std::panic::resume_unwind(std::boxed::Box::new(()));
                });
            }));
            assert!(result.is_err());
            assert!(cleared(&workspace.owner));
            let mut output = [0; $width];
            workspace.with(|state| state.finalize_public(&mut output, Sha3PublicDeclassification::acknowledge()))?;
            assert!(cleared(&workspace.owner));
            assert_eq!(&output, crate::$reference(b"").map_err(|_| HardenedSha3Error::MessageTooLong)?.as_bytes());
            Ok(())
        }
    };
}

campaign!(
    sha224,
    Sha3_224Workspace,
    Sha3_224,
    28,
    sha3_224,
    sha3_224_bits
);
campaign!(
    sha256,
    Sha3_256Workspace,
    Sha3_256,
    32,
    sha3_256,
    sha3_256_bits
);
campaign!(
    sha384,
    Sha3_384Workspace,
    Sha3_384,
    48,
    sha3_384,
    sha3_384_bits
);
campaign!(
    sha512,
    Sha3_512Workspace,
    Sha3_512,
    64,
    sha3_512,
    sha3_512_bits
);

#[test]
fn forgotten_handle_unwind_and_failed_update_clear_scope() -> Result<(), HardenedSha3Error> {
    let mut workspace = Sha3_256Workspace::new();
    workspace.with(|mut state| {
        state.update(b"secret")?;
        core::mem::forget(state);
        Ok::<(), HardenedSha3Error>(())
    })?;
    assert!(cleared(&workspace.owner));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        workspace.with(|mut state| {
            assert!(state.update(b"secret").is_ok());
            core::mem::forget(state);
            std::panic::resume_unwind(std::boxed::Box::new(()));
        });
    }));
    assert!(result.is_err());
    assert!(cleared(&workspace.owner));
    workspace.with(|mut state| {
        state.owner.message_length.fill(0xff);
        assert_eq!(state.update(b"x"), Err(HardenedSha3Error::MessageTooLong));
        assert!(cleared(state.owner));
        assert_eq!(state.update(&[]), Err(HardenedSha3Error::StateConsumed));
    });
    assert!(cleared(&workspace.owner));
    Ok(())
}
