//! Development borrowed-engine probes, not native qualification.
use brynja_hash_sha3::hardened_execution::{Error, in_place::*};

macro_rules! probe {
    ($name:ident, $workspace:ident, $width:literal) => {
        /// Borrows sponge, CPU scratch and staging across secret operations.
        #[inline(never)]
        pub extern "C" fn $name(
            workspace: &mut $workspace<'_>,
            input: &[u8; 256],
            output: &mut [u8; $width],
        ) -> u8 {
            let result = workspace.with(|mut state| {
                state.update(input)?;
                drop(state.finalize_secret(output)?);
                Ok::<(), Error>(())
            });
            u8::from(!matches!(result, Ok(Ok(()))))
        }
    };
}
probe!(execution224, Sha3_224Workspace, 28);
probe!(execution256, Sha3_256Workspace, 32);
probe!(execution384, Sha3_384Workspace, 48);
probe!(execution512, Sha3_512Workspace, 64);

macro_rules! xof_probe {
    ($name:ident, $workspace:ident, $state:ident, $kind:ident) => {
        /// Keeps the sponge and output stage borrowed through the reader transition.
        #[inline(never)]
        pub extern "C" fn $name(workspace: &mut $workspace<'_>, input: &[u8; 256], output: &mut [u8; 337]) -> u8 {
            let operation = |mut state: $state<'_, '_>| {
                state.update(input)?;
                let mut reader = state.finalize_xof()?;
                drop(reader.squeeze_secret(output)?);
                Ok::<(), Error>(())
            };
            let result = xof_probe!(@scope workspace, $kind, operation);
            u8::from(!matches!(result, Ok(Ok(()))))
        }
    };
    (@scope $w:ident, shake, $operation:ident) => { $w.with($operation) };
    (@scope $w:ident, custom, $operation:ident) => { $w.with(b"", b"domain", $operation) };
}
xof_probe!(execution_shake128, Shake128Workspace, Shake128, shake);
xof_probe!(execution_shake256, Shake256Workspace, Shake256, shake);
xof_probe!(execution_cshake128, Cshake128Workspace, Cshake128, custom);
xof_probe!(execution_cshake256, Cshake256Workspace, Cshake256, custom);

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use brynja_crypto_cpu::static_execution::{Authority, Kernel};
    use brynja_hash_sha3::hardened_execution::KeccakSession;

    fn campaign<'a>(
        mut session: impl FnMut() -> Result<KeccakSession<'a>, Error>,
    ) -> Result<(), Error> {
        macro_rules! check {
            ($workspace:ident, $reference:ident, $probe:ident, $width:literal) => {{
                let mut workspace = $workspace::new(session()?)?;
                let mut output = [0xa5; $width];
                assert_eq!($probe(&mut workspace, &[0xa6; 256], &mut output), 0);
                assert_eq!(output, [0; $width]);
                let secret = workspace.with(|mut state| {
                    state.update(b"abc")?;
                    state.finalize_secret(&mut output)
                })??;
                assert_eq!(
                    secret.expose(),
                    brynja_hash_sha3::$reference(b"abc")
                        .map_err(|_| Error::Terminal)?
                        .as_bytes()
                );
                drop(secret);
                assert_eq!(output, [0; $width]);
            }};
        }
        check!(Sha3_224Workspace, sha3_224, execution224, 28);
        check!(Sha3_256Workspace, sha3_256, execution256, 32);
        check!(Sha3_384Workspace, sha3_384, execution384, 48);
        check!(Sha3_512Workspace, sha3_512, execution512, 64);
        macro_rules! xof {
            ($workspace:ident, $probe:ident) => {{
                let mut workspace = $workspace::new(session()?)?;
                let mut output = [0xa5; 337];
                assert_eq!($probe(&mut workspace, &[0xa6; 256], &mut output), 0);
                assert_eq!(output, [0; 337]);
            }};
        }
        xof!(Shake128Workspace, execution_shake128);
        xof!(Shake256Workspace, execution_shake256);
        xof!(Cshake128Workspace, execution_cshake128);
        xof!(Cshake256Workspace, execution_cshake256);
        let mut workspace = Cshake128Workspace::new(session()?)?;
        let mut output = [0xa5; 4];
        let secret = workspace.with(b"", b"Email Signature", |mut state| {
            state.update(&[0, 1, 2, 3])?;
            state.finalize_xof()?.squeeze_secret(&mut output)
        })??;
        assert_eq!(secret.expose(), [0xc1, 0xc3, 0x69, 0x25]);
        drop(secret);
        assert_eq!(output, [0; 4]);
        Ok(())
    }

    #[test]
    fn available_static_and_hosted_scoped_keccak() -> Result<(), Error> {
        let kernel = if cfg!(target_arch = "aarch64") {
            Kernel::ArmKeccak
        } else {
            Kernel::X86Keccak
        };
        let selected = Authority::new(kernel);
        if std::env::var_os("BRYNJA_REQUIRE_SCOPED_KECCAK").is_some() {
            assert!(selected.is_ok());
        }
        if let Ok(owner) = selected {
            campaign(|| KeccakSession::from_static(&owner).map_err(Error::Backend))?;
        }
        #[cfg(feature = "hosted")]
        {
            use brynja_crypto_cpu_std::execution as host;
            let selected = host::Authority::new(kernel, host::Mode::Require);
            if std::env::var_os("BRYNJA_REQUIRE_SCOPED_KECCAK_HOSTED").is_some() {
                assert!(selected.is_ok());
            }
            match selected {
                Ok(owner) => {
                    let session = || {
                        KeccakSession::from_runtime(
                            owner
                                .session()
                                .map_err(|_| Error::Terminal)?
                                .ok_or(Error::Terminal)?,
                        )
                        .map_err(Error::Backend)
                    };
                    campaign(session)?;
                    let mut workspace = Sha3_256Workspace::new(session()?)?;
                    let mut output = [0xa5; 32];
                    workspace.with(|mut state| {
                        state.update(b"secret")?;
                        owner.quarantine();
                        assert!(matches!(
                            state.finalize_secret(&mut output),
                            Err(Error::Backend(_))
                        ));
                        Ok::<(), Error>(())
                    })??;
                    assert_eq!(output, [0; 32]);
                    let mut called = false;
                    assert!(matches!(
                        workspace.with(|_| called = true),
                        Err(Error::Backend(_))
                    ));
                    assert!(!called);
                    let owner = host::Authority::new(kernel, host::Mode::Require)
                        .map_err(|_| Error::Terminal)?;
                    let session = KeccakSession::from_runtime(
                        owner
                            .session()
                            .map_err(|_| Error::Terminal)?
                            .ok_or(Error::Terminal)?,
                    )
                    .map_err(Error::Backend)?;
                    let mut workspace = Shake128Workspace::new(session)?;
                    workspace.with(|state| {
                        let mut reader = state.finalize_xof()?;
                        owner.quarantine();
                        output.fill(0xa5);
                        assert!(matches!(
                            reader.squeeze_secret(&mut output),
                            Err(Error::Backend(_))
                        ));
                        Ok::<(), Error>(())
                    })??;
                    assert_eq!(output, [0; 32]);
                }
                Err(host::Error::Unavailable(_)) => {}
                Err(_) => return Err(Error::Terminal),
            }
        }
        Ok(())
    }
}
