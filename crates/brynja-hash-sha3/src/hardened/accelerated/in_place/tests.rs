extern crate std;
use super::*;
use brynja_crypto_cpu::static_execution::{Authority, Kernel};

pub(super) fn authority() -> Result<Option<Authority>, Error> {
    let kernel = if cfg!(target_arch = "aarch64") {
        Kernel::ArmKeccak
    } else {
        Kernel::X86Keccak
    };
    let result = Authority::new(kernel);
    if std::env::var_os("BRYNJA_REQUIRE_SCOPED_KECCAK").is_some() {
        return result.map(Some).map_err(Error::Backend);
    }
    Ok(result.ok())
}
pub(super) fn session(owner: &Authority) -> Result<KeccakSession<'_>, Error> {
    KeccakSession::from_static(owner).map_err(Error::Backend)
}
fn cleared(storage: &Storage<'_>) -> bool {
    storage.engine.cleared_for_test() && storage.stage.0.iter().all(|b| *b == 0)
}
pub(super) fn public() -> Sha3PublicDeclassification {
    Sha3PublicDeclassification::acknowledge()
}

macro_rules! campaign {
    ($workspace:ident, $reference:ident, $bits:ident, $rate:literal, $width:literal, $owner:ident) => {{
        let mut workspace = $workspace::new(session(&$owner)?)?;
        let address = core::ptr::from_ref(&workspace.storage.engine);
        let staging = core::ptr::from_ref(&workspace.storage.stage);
        let report = workspace.report();
        for length in [0, 1, $rate - 2, $rate - 1, $rate, $rate + 1, 2 * $rate - 1, 2 * $rate, 3 * $rate + 5] {
            let input = std::vec![0xa6; length];
            let expected = crate::$reference(&input).map_err(|_| Error::Terminal)?;
            let mut output = [0xa5; $width];
            for chunk in [1, 17, $rate, $rate + 1] {
                let secret = workspace.with(|mut state| {
                    assert_eq!(core::ptr::from_ref(&state.storage.engine), address);
                    assert_eq!(core::ptr::from_ref(&state.storage.stage), staging);
                    for part in input.chunks(chunk) { state.update(&[])?; state.update(part)?; }
                    state.finalize_secret(&mut output)
                })??;
                assert_eq!(secret.expose(), expected.as_bytes());
                assert!(cleared(&workspace.storage)); drop(secret);
                assert_eq!(output, [0; $width]);
                assert_eq!(workspace.report(), report);
            }
            for valid in 1..=8 {
                let mut all = input.clone(); all.push(1);
                let bits = Fips202BitString::new(&all, valid).map_err(|_| Error::Terminal)?;
                let expected = crate::$bits(bits).map_err(|_| Error::Terminal)?;
                let tail = Fips202BitString::new(&[1], valid).map_err(|_| Error::Terminal)?;
                let secret = workspace.with(|mut state| { state.update(&input)?; state.finalize_bits_secret(tail, &mut output) })??;
                assert_eq!(secret.expose(), expected.as_bytes()); drop(secret);
                assert_eq!(output, [0; $width]);
                workspace.with(|state| state.finalize_bits_public(bits, &mut output, public()))??;
                assert_eq!(output.as_slice(), expected.as_bytes()); assert!(cleared(&workspace.storage));
            }
            workspace.with(|mut state| { state.update(&input)?; state.finalize_public(&mut output, public()) })??;
            assert_eq!(output.as_slice(), expected.as_bytes());
        }
        for width in 0..=65 {
            if width == $width { continue; }
            let mut output = std::vec![0xa5; width];
            assert!(matches!(workspace.with(|mut state| { state.update(b"secret")?; state.finalize_secret(&mut output) })?, Err(Error::OutputLength)));
            assert!(output.iter().all(|b| *b == 0)); assert!(cleared(&workspace.storage));
            output.fill(0xa5);
            assert_eq!(workspace.with(|state| state.finalize_public(&mut output, public()))?, Err(Error::OutputLength));
            assert!(output.iter().all(|b| *b == 0xa5)); assert!(cleared(&workspace.storage));
        }
    }};
}

#[test]
fn scoped_fixed_execution_all_identities_bytes_bits_and_reuse() -> Result<(), Error> {
    let Some(owner) = authority()? else {
        return Ok(());
    };
    campaign!(Sha3_224Workspace, sha3_224, sha3_224_bits, 144, 28, owner);
    campaign!(Sha3_256Workspace, sha3_256, sha3_256_bits, 136, 32, owner);
    campaign!(Sha3_384Workspace, sha3_384, sha3_384_bits, 104, 48, owner);
    campaign!(Sha3_512Workspace, sha3_512, sha3_512_bits, 72, 64, owner);
    Ok(())
}

#[test]
fn scoped_fixed_execution_cleanup_forget_unwind_and_errors() -> Result<(), Error> {
    let Some(owner) = authority()? else {
        return Ok(());
    };
    let mut workspace = Sha3_256Workspace::new(session(&owner)?)?;
    for mode in 0..4 {
        workspace.with(|mut state| {
            state.update(b"secret")?;
            state.storage.stage.0.fill(0xa5);
            match mode {
                0 => state.cancel(),
                1 => drop(state),
                2 => core::mem::forget(state),
                _ => {
                    state.storage.engine.overflow_message_for_test();
                    assert_eq!(state.update(b"x"), Err(Error::LengthOverflow));
                    assert!(cleared(state.storage));
                    assert_eq!(state.update(&[]), Err(Error::Terminal));
                    core::mem::forget(state);
                }
            }
            Ok::<(), Error>(())
        })??;
        assert!(cleared(&workspace.storage));
    }
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = workspace.with(|mut state| {
            assert!(state.update(b"secret").is_ok());
            state.storage.stage.0.fill(0xa5);
            core::mem::forget(state);
            std::panic::resume_unwind(std::boxed::Box::new(()));
        });
    }));
    assert!(caught.is_err());
    assert!(cleared(&workspace.storage));
    workspace.storage.engine.restart()?;
    let mut state = Sha3_256 {
        storage: &mut workspace.storage,
    };
    state.update(b"secret")?;
    state.storage.stage.0.fill(0xa5);
    state.cancel();
    assert!(cleared(&workspace.storage));
    for secret in [false, true] {
        for failed_update in [false, true] {
            let mut output = [0xa5; 32];
            workspace.with(|mut state| {
                state.update(b"secret")?;
                if failed_update {
                    state.storage.engine.overflow_message_for_test();
                    assert_eq!(state.update(b"x"), Err(Error::LengthOverflow));
                } else {
                    state.storage.engine.remaining_permutations = Some(0);
                }
                if secret {
                    assert!(matches!(
                        state.finalize_secret(&mut output),
                        Err(Error::Terminal)
                    ));
                } else {
                    assert_eq!(
                        state.finalize_public(&mut output, public()),
                        Err(Error::Terminal)
                    );
                }
                Ok::<(), Error>(())
            })??;
            assert_eq!(output, [if secret { 0 } else { 0xa5 }; 32]);
            assert!(cleared(&workspace.storage));
            workspace.storage.engine.remaining_permutations = None;
        }
    }
    let mut output = [0; 32];
    workspace.with(|mut state| {
        state.update(b"abc")?;
        state.finalize_public(&mut output, public())
    })??;
    assert_eq!(
        output.as_slice(),
        crate::sha3_256(b"abc")
            .map_err(|_| Error::Terminal)?
            .as_bytes()
    );
    Ok(())
}

#[test]
fn scoped_fixed_execution_revocation_never_reuses_or_falls_back() -> Result<(), Error> {
    for secret in [false, true] {
        let Some(owner) = authority()? else {
            return Ok(());
        };
        let mut workspace = Sha3_256Workspace::new(session(&owner)?)?;
        let mut output = [0xa5; 32];
        workspace.with(|mut state| {
            state.update(b"secret")?;
            owner.quarantine();
            if secret {
                assert!(matches!(
                    state.finalize_secret(&mut output),
                    Err(Error::Backend(_))
                ));
            } else {
                assert!(matches!(
                    state.finalize_public(&mut output, public()),
                    Err(Error::Backend(_))
                ));
            }
            Ok::<(), Error>(())
        })??;
        assert_eq!(output, [if secret { 0 } else { 0xa5 }; 32]);
        assert!(cleared(&workspace.storage));
        let mut called = false;
        assert!(matches!(
            workspace.with(|_| called = true),
            Err(Error::Backend(_))
        ));
        assert!(!called);
        assert!(cleared(&workspace.storage));
    }
    Ok(())
}
