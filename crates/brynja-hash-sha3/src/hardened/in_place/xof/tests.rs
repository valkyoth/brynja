extern crate std;
use super::*;
use crate::hardened::in_place::tests::cleared;

fn authority() -> Sha3PublicDeclassification {
    Sha3PublicDeclassification::acknowledge()
}
fn bits(input: &[u8], valid: u8) -> Fips202BitString<'_> {
    Fips202BitString::new(input, valid).unwrap_or_else(|_| unreachable!())
}

macro_rules! scoped {
    ($workspace:ident, shake, $n:expr, $s:expr, $operation:expr) => {{
        let _ = ($n, $s);
        $workspace.with($operation)
    }};
    ($workspace:ident, cshake, $n:expr, $s:expr, $operation:expr) => {
        $workspace.with_bits($n, $s, $operation)?
    };
}
macro_rules! reference {
    ($reference:ident, shake, $n:expr, $s:expr) => {
        crate::$reference::new()
    };
    ($reference:ident, cshake, $n:expr, $s:expr) => {
        crate::$reference::new_bits($n, $s)?
    };
}

macro_rules! campaign {
    ($test:ident, $workspace:ident, $reference:ident, $kind:ident, $rate:expr) => {
        #[test]
        fn $test() -> Result<(), HardenedSha3Error> {
            let mut workspace = $workspace::new();
            let address = core::ptr::from_ref(&workspace.owner);
            for length in [0, 1, 7, 71, 135, 136, 137, 167, 168, 169, 335, 1024] {
                for valid in 1u8..=8 {
                    let mut input = std::vec![0xa6; length];
                    input.push(if valid == 8 { 0xff } else { (1u8 << valid) - 1 });
                    // Vary both domain strings across all final-bit widths.
                    let name = [if valid == 8 { 0xff } else { (1u8 << valid) - 1 }];
                    let n = bits(&name, valid);
                    let s = bits(&input, valid);
                    let mut reference = reference!($reference, $kind, n, s);
                    reference.update(b"prefix")?;
                    let mut reference = reference.finalize_bits_xof(bits(&input, valid))?;
                    let mut expected = std::vec![0; $rate * 3 + 19];
                    reference.squeeze_public(&mut expected, authority())?;
                    let mut tail = [0xa5; 3];
                    let secret = scoped!(workspace, $kind, n, s, |mut state| {
                        assert_eq!(core::ptr::from_ref(&*state.inner.owner), address);
                        state.update(b"pre")?;
                        state.update(&[])?;
                        state.update(b"fix")?;
                        let mut reader = state.finalize_bits_xof(bits(&input, valid))?;
                        assert_eq!(core::ptr::from_ref(&*reader.inner.owner), address);
                        reader.squeeze_public(&mut [], authority())?;
                        drop(reader.squeeze_secret(&mut [])?);
                        let mut offset = 0;
                        for width in [1, $rate - 1, 1, $rate + 2, $rate + 13] {
                            let mut out = std::vec![0xa5; width];
                            if offset % 2 == 0 {
                                let secret = reader.squeeze_secret(&mut out)?;
                                assert_eq!(secret.expose(), expected.get(offset..offset + width).ok_or(HardenedSha3Error::OutputLength)?);
                                drop(secret);
                                assert!(out.iter().all(|byte| *byte == 0));
                            } else {
                                reader.squeeze_public(&mut out, authority())?;
                                assert_eq!(out, expected.get(offset..offset + width).ok_or(HardenedSha3Error::OutputLength)?);
                            }
                            offset += width;
                        }
                        assert_eq!(offset, expected.len() - 3);
                        reader.squeeze_final_bits_secret(Fips202Output::new(&mut tail, valid).map_err(|_| HardenedSha3Error::OutputLength)?)
                    })?;
                    let mut final_expected = [0; 3];
                    let mut reference = reference!($reference, $kind, n, s);
                    reference.update(b"prefix")?;
                    let mut reference = reference.finalize_bits_xof(bits(&input, valid))?;
                    reference.squeeze_public(expected.get_mut(..$rate * 3 + 16).ok_or(HardenedSha3Error::OutputLength)?, authority())?;
                    reference.squeeze_final_bits_public(Fips202Output::new(&mut final_expected, valid).map_err(|_| HardenedSha3Error::OutputLength)?, authority())?;
                    assert_eq!(secret.expose(), final_expected);
                    drop(secret);
                    assert_eq!(tail, [0; 3]);
                    assert!(cleared(&workspace.owner));
                    // Public final bits take the same consuming transition.
                    let mut out = [0xa5; 3];
                    scoped!(workspace, $kind, n, s, |state| {
                        let reader = state.finalize_bits_xof(bits(&input, valid))?;
                        reader.squeeze_final_bits_public(Fips202Output::new(&mut out, valid).map_err(|_| HardenedSha3Error::OutputLength)?, authority())
                    })?;
                    let reference = reference!($reference, $kind, n, s);
                    let reference = reference.finalize_bits_xof(bits(&input, valid))?;
                    reference.squeeze_final_bits_public(Fips202Output::new(&mut final_expected, valid).map_err(|_| HardenedSha3Error::OutputLength)?, authority())?;
                    assert_eq!(out, final_expected);
                    assert!(cleared(&workspace.owner));
                }
            }
            // All four constructions support byte-only finalization and reuse.
            let n = bits(&[], 0);
            let s = bits(&[], 0);
            for disposition in 0..5 {
                scoped!(workspace, $kind, n, s, |mut state| {
                    state.update(b"confidential")?;
                    if disposition == 0 { state.cancel(); }
                    else if disposition == 1 { core::mem::forget(state); }
                    else {
                        let mut reader = state.finalize_xof()?;
                        reader.squeeze_public(&mut [0; 1], authority())?;
                        match disposition {
                            2 => reader.cancel(),
                            3 => drop(reader),
                            _ => core::mem::forget(reader),
                        }
                    }
                    Ok::<(), HardenedSha3Error>(())
                })?;
                assert!(cleared(&workspace.owner));
            }
            // Direct handles ensure the outer scope guard cannot mask broken Drop.
            let mut inner = Borrowed { owner: &mut workspace.owner, active: true, thread_bound: PhantomData };
            inner.update(b"secret")?;
            drop(inner);
            assert!(cleared(&workspace.owner));
            for secret in [false, true] {
                let mut output = [0xa5; 3];
                scoped!(workspace, $kind, n, s, |state| {
                    let reader = state.finalize_xof()?;
                    reader.inner.owner.output_length.fill(0xff);
                    let out = Fips202Output::new(&mut output, 3).map_err(|_| HardenedSha3Error::OutputLength)?;
                    if secret {
                        assert!(matches!(reader.squeeze_final_bits_secret(out), Err(HardenedSha3Error::OutputTooLong)));
                    } else {
                        assert_eq!(reader.squeeze_final_bits_public(out, authority()), Err(HardenedSha3Error::OutputTooLong));
                    }
                    Ok::<(), HardenedSha3Error>(())
                })?;
                assert_eq!(output, if secret { [0; 3] } else { [0xa5; 3] });
                assert!(cleared(&workspace.owner));
            }
            scoped!(workspace, $kind, n, s, |state| {
                let reader = state.finalize_xof()?;
                drop(reader.squeeze_final_bits_secret(Fips202Output::new(&mut [], 0).map_err(|_| HardenedSha3Error::OutputLength)?)?);
                Ok::<(), HardenedSha3Error>(())
            })?;
            assert!(cleared(&workspace.owner));
            Ok(())
        }
    };
}
campaign!(shake128, Shake128Workspace, HardenedShake128, shake, 168);
campaign!(shake256, Shake256Workspace, HardenedShake256, shake, 136);
campaign!(
    cshake128,
    Cshake128Workspace,
    HardenedCshake128,
    cshake,
    168
);
campaign!(
    cshake256,
    Cshake256Workspace,
    HardenedCshake256,
    cshake,
    136
);

#[test]
fn reader_failures_forgetting_and_unwind_clear_in_place() -> Result<(), HardenedSha3Error> {
    let mut workspace = Shake128Workspace::new();
    for secret in [false, true] {
        workspace.with(|state| {
            let mut reader = state.finalize_xof()?;
            reader.inner.owner.output_length.fill(0xff);
            let mut output = [0xa5; 169];
            if secret {
                assert!(matches!(
                    reader.squeeze_secret(&mut output),
                    Err(HardenedSha3Error::OutputTooLong)
                ));
                assert_eq!(output, [0; 169]);
            } else {
                assert_eq!(
                    reader.squeeze_public(&mut output, authority()),
                    Err(HardenedSha3Error::OutputTooLong)
                );
                assert_eq!(output, [0xa5; 169]);
            }
            assert!(cleared(reader.inner.owner));
            assert_eq!(
                reader.squeeze_public(&mut output, authority()),
                Err(HardenedSha3Error::StateConsumed)
            );
            assert!(matches!(
                reader.squeeze_secret(&mut output),
                Err(HardenedSha3Error::StateConsumed)
            ));
            assert_eq!(output, [0; 169]);
            core::mem::forget(reader);
            Ok::<(), HardenedSha3Error>(())
        })?;
        assert!(cleared(&workspace.owner));
    }
    workspace.with(|mut state| {
        state.inner.owner.message_length.fill(0xff);
        assert_eq!(state.update(b"x"), Err(HardenedSha3Error::MessageTooLong));
        assert!(cleared(state.inner.owner));
        assert_eq!(state.update(&[]), Err(HardenedSha3Error::StateConsumed));
        assert!(matches!(
            state.finalize_xof(),
            Err(HardenedSha3Error::StateConsumed)
        ));
    });
    workspace.with(|state| {
        state.inner.owner.message_length.fill(0xff);
        assert!(matches!(
            state.finalize_bits_xof(bits(b"x", 8)),
            Err(HardenedSha3Error::MessageTooLong)
        ));
    });
    assert!(cleared(&workspace.owner));
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        workspace.with(|mut state| {
            assert!(state.update(b"secret").is_ok());
            let reader = state.finalize_xof().unwrap_or_else(|_| unreachable!());
            core::mem::forget(reader);
            std::panic::resume_unwind(std::boxed::Box::new(()));
        });
    }));
    assert!(unwind.is_err());
    assert!(cleared(&workspace.owner));
    // Test operation unwind independently of the outer guard and handle destructor.
    let mut inner = Borrowed {
        owner: &mut workspace.owner,
        active: true,
        thread_bound: PhantomData,
    };
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = inner.run::<()>(|owner| {
            owner.sponge_lanes.fill(0x55);
            std::panic::resume_unwind(std::boxed::Box::new(()));
        });
    }));
    assert!(unwind.is_err());
    assert!(cleared(inner.owner));
    assert_eq!(inner.update(&[]), Err(HardenedSha3Error::StateConsumed));
    Ok(())
}

#[test]
fn cshake_empty_domain_matches_shake_and_byte_setup_matches_bits() -> Result<(), HardenedSha3Error>
{
    let mut cshake = Cshake128Workspace::new();
    let mut shake = Shake128Workspace::new();
    let mut a = [0; 337];
    let mut b = [0; 337];
    cshake.with(b"", b"", |state| {
        state.finalize_xof()?.squeeze_public(&mut a, authority())
    })??;
    shake.with(|state| state.finalize_xof()?.squeeze_public(&mut b, authority()))?;
    assert_eq!(a, b);
    cshake.with(b"function", b"custom", |state| {
        state.finalize_xof()?.squeeze_public(&mut a, authority())
    })??;
    cshake.with_bits(bits(b"function", 8), bits(b"custom", 8), |state| {
        state.finalize_xof()?.squeeze_public(&mut b, authority())
    })??;
    assert_eq!(a, b);
    assert!(cleared(&cshake.owner));
    Ok(())
}
