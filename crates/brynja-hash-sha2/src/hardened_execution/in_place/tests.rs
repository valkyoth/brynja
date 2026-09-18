extern crate std;
use super::*;
use brynja_crypto_cpu::static_execution::{Authority, Kernel};

fn cleared(owner: &HardenedSha2Owner) -> bool {
    owner
        .chaining_state
        .iter()
        .chain(&owner.partial_input)
        .chain(&owner.message_length)
        .chain(&owner.phase)
        .chain(&owner.message_schedule)
        .chain(&owner.block_copy)
        .chain(&owner.padding_block)
        .chain(&owner.output_staging)
        .all(|byte| *byte == 0)
}
fn authority(wide: bool) -> Option<Authority> {
    let kernel = match (cfg!(target_arch = "aarch64"), wide) {
        (false, false) => Kernel::X86Sha256,
        (false, true) => Kernel::X86Sha512,
        (true, false) => Kernel::ArmSha256,
        (true, true) => Kernel::ArmSha512,
    };
    let result = Authority::new(kernel).ok();
    if std::env::var_os("BRYNJA_REQUIRE_SCOPED_SHA2").is_some()
        && (!wide || cfg!(target_arch = "aarch64") || cfg!(target_feature = "sha512"))
    {
        assert!(result.is_some(), "required compiled scoped SHA-2 kernel");
    }
    result
}
fn execution(owner: Option<&Authority>) -> Result<Execution<'_>, Error> {
    owner.map_or_else(|| Ok(Execution::portable()), Execution::from_static)
}
fn declassify() -> PublicDeclassification {
    PublicDeclassification::acknowledge()
}

macro_rules! campaign {
    ($workspace:ident, $ordinary:ident, $bits:ident, $wide:expr, $width:literal, $block:literal) => {{
        let cpu = authority($wide);
        for owner in [None, cpu.as_ref()] {
            let mut workspace = $workspace::new(execution(owner)?)?;
            let address = core::ptr::from_ref(&workspace.engine);
            let route = workspace.route();
            for length in [0, 1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 255, 256, 1024] {
                let input = std::vec![0xa6; length];
                let expected = crate::$ordinary(&input).map_err(|_| Error::Failed)?;
                let mut output = [0xa5; $width];
                for chunk in [1, 17, 63, 128, 257] {
                    let secret = workspace.with(|mut state| {
                        assert_eq!(core::ptr::from_ref(&*state.engine), address);
                        for part in input.chunks(chunk) { state.update(&[])?; state.update(part)?; }
                        state.finalize_secret(&mut output)
                    })??;
                    assert!(cleared(&workspace.engine.owner));
                    assert_eq!(secret.digest.expose(), expected.as_bytes());
                    assert_eq!(secret.report.route, route);
                    assert_eq!(secret.report.message_blocks, (length / $block) as u128);
                    assert_eq!(secret.report.padding_blocks, if length % $block < $block - if $wide {16} else {8} {1} else {2});
                    assert_eq!(secret.report.portable_iv_blocks, 0);
                    drop(secret); assert_eq!(output, [0; $width]);
                }
                workspace.with(|mut state| { state.update(&input)?; state.finalize_public(&mut output, declassify()) })??;
                assert_eq!(output.as_slice(), expected.as_bytes());
                assert!(cleared(&workspace.engine.owner));
                for valid in 1..=8 {
                    let mut bytes = input.clone(); bytes.push(0x80);
                    let bits = BitString::new(&bytes, valid).map_err(|_| Error::Failed)?;
                    let expected = crate::$bits(bits).map_err(|_| Error::Failed)?;
                    let secret = workspace.with(|mut state| {
                        state.update(&input)?;
                        state.finalize_bits_secret(BitString::new(&[0x80], valid).map_err(|_| Error::Failed)?, &mut output)
                    })??;
                    assert_eq!(secret.digest.expose(), expected.as_bytes());
                    assert_eq!(secret.report.route, route); drop(secret);
                    assert_eq!(output, [0; $width]);
                    workspace.with(|state| state.finalize_bits_public(bits, &mut output, declassify()))??;
                    assert_eq!(output.as_slice(), expected.as_bytes());
                    assert!(cleared(&workspace.engine.owner));
                }
            }
            for width in 0..=65 {
                if width == $width { continue; }
                let mut output = std::vec![0xa5; width];
                let result = workspace.with(|mut state| { state.update(b"secret")?; state.finalize_secret(&mut output) })?;
                assert!(matches!(result, Err(Error::OutputLength))); drop(result);
                assert!(output.iter().all(|byte| *byte == 0)); assert!(cleared(&workspace.engine.owner));
                output.fill(0xa5);
                assert_eq!(workspace.with(|state| state.finalize_public(&mut output, declassify()))?, Err(Error::OutputLength));
                assert!(output.iter().all(|byte| *byte == 0xa5)); assert!(cleared(&workspace.engine.owner));
            }
        }
    }};
}

#[test]
fn scoped_execution_named_bytes_bits_reports_and_outputs() -> Result<(), Error> {
    campaign!(Sha224Workspace, sha224, sha224_bits, false, 28, 64);
    campaign!(Sha256Workspace, sha256, sha256_bits, false, 32, 64);
    campaign!(Sha384Workspace, sha384, sha384_bits, true, 48, 128);
    campaign!(Sha512Workspace, sha512, sha512_bits, true, 64, 128);
    campaign!(
        Sha512_224Workspace,
        sha512_224,
        sha512_224_bits,
        true,
        28,
        128
    );
    campaign!(
        Sha512_256Workspace,
        sha512_256,
        sha512_256_bits,
        true,
        32,
        128
    );
    Ok(())
}

#[test]
fn scoped_execution_forget_unwind_and_terminal_failure() -> Result<(), Error> {
    let mut workspace = Sha256Workspace::new(Execution::portable())?;
    for mode in 0..5 {
        workspace.with(|mut state| {
            state.update(b"confidential")?;
            match mode {
                0 => state.cancel(),
                1 => drop(state),
                2 => core::mem::forget(state),
                _ => {
                    if mode == 3 {
                        state.engine.owner.message_length[..8].fill(0xff);
                    } else {
                        state.engine.report.message_blocks = u128::MAX;
                    }
                    assert_eq!(state.update(&[0; 128]), Err(Error::MessageTooLong));
                    assert!(cleared(&state.engine.owner));
                    assert_eq!(state.update(&[]), Err(Error::Failed));
                    core::mem::forget(state);
                }
            }
            Ok::<(), Error>(())
        })??;
        assert!(cleared(&workspace.engine.owner));
    }
    for public in [false, true] {
        for tail in [false, true] {
            let mut output = [0xa5; 32];
            workspace.with(|mut state| {
                state.engine.owner.message_length[..8].fill(0xff);
                assert!(state.update(b"x").is_err());
                let bits = BitString::new(&[0x80], 1).map_err(|_| Error::Failed)?;
                if public {
                    let result = if tail {
                        state.finalize_bits_public(bits, &mut output, declassify())
                    } else {
                        state.finalize_public(&mut output, declassify())
                    };
                    assert_eq!(result, Err(Error::Failed));
                } else {
                    let result = if tail {
                        state.finalize_bits_secret(bits, &mut output)
                    } else {
                        state.finalize_secret(&mut output)
                    };
                    assert!(matches!(result, Err(Error::Failed)));
                }
                Ok::<(), Error>(())
            })??;
            assert_eq!(output, [if public { 0xa5 } else { 0 }; 32]);
            assert!(cleared(&workspace.engine.owner));
        }
    }
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = workspace.with(|mut state| {
            assert!(state.update(b"secret").is_ok());
            core::mem::forget(state);
            std::panic::resume_unwind(std::boxed::Box::new(()));
        });
    }));
    assert!(caught.is_err());
    assert!(cleared(&workspace.engine.owner));
    workspace.engine.restart()?;
    let mut state = Sha256 {
        engine: &mut workspace.engine,
    };
    state.update(b"secret")?;
    state.cancel();
    assert!(cleared(&workspace.engine.owner));
    let mut output = [0; 32];
    workspace.with(|mut state| {
        state.update(b"abc")?;
        state.finalize_public(&mut output, declassify())
    })??;
    assert_eq!(
        output.as_slice(),
        crate::sha256(b"abc").map_err(|_| Error::Failed)?.as_bytes()
    );
    Ok(())
}

#[test]
fn scoped_execution_revocation_rejects_reuse_and_wrong_family() -> Result<(), Error> {
    let Some(owner) = authority(false) else {
        return Ok(());
    };
    assert!(matches!(
        Sha512Workspace::new(execution(Some(&owner))?),
        Err(Error::Backend(_))
    ));
    let mut workspace = Sha256Workspace::new(execution(Some(&owner))?)?;
    let mut output = [0xa5; 32];
    workspace.with(|mut state| {
        state.update(b"secret")?;
        owner.quarantine();
        assert!(matches!(state.update(&[]), Err(Error::Backend(_))));
        assert!(cleared(&state.engine.owner));
        assert_eq!(state.update(b"retry"), Err(Error::Failed));
        assert!(matches!(
            state.finalize_secret(&mut output),
            Err(Error::Failed)
        ));
        Ok::<(), Error>(())
    })??;
    assert_eq!(output, [0; 32]);
    let mut called = false;
    output.fill(0xa5);
    assert!(matches!(
        workspace.with(|_| {
            called = true;
            output.fill(0);
        }),
        Err(Error::Backend(_))
    ));
    assert!(!called);
    assert_eq!(output, [0xa5; 32]);
    assert!(cleared(&workspace.engine.owner));
    let owner = authority(false).ok_or(Error::Failed)?;
    let mut workspace = Sha256Workspace::new(execution(Some(&owner))?)?;
    workspace.with(|mut state| {
        state.update(b"secret")?;
        owner.quarantine();
        output.fill(0xa5);
        assert!(matches!(
            state.finalize_public(&mut output, declassify()),
            Err(Error::Backend(_))
        ));
        Ok::<(), Error>(())
    })??;
    assert_eq!(output, [0xa5; 32]);
    assert!(cleared(&workspace.engine.owner));
    Ok(())
}
