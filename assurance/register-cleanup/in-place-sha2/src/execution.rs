//! Development ABI and packaged-consumer probes, not platform qualification.
use brynja_hash_sha2::hardened_execution::{Error, in_place::*};

macro_rules! probe {
    ($name:ident, $workspace:ident, $width:literal) => {
        /// Borrows the engine and CPU scratch through secret input and output.
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
probe!(execution224, Sha224Workspace, 28);
probe!(execution256, Sha256Workspace, 32);
probe!(execution384, Sha384Workspace, 48);
probe!(execution512, Sha512Workspace, 64);
probe!(execution512_224, Sha512_224Workspace, 28);
probe!(execution512_256, Sha512_256Workspace, 32);

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use brynja_hash_sha2::hardened_execution::{Execution, Route};

    macro_rules! check {
        ($workspace:ident, $reference:ident, $width:literal, $probe:ident, $wide:expr) => {{
            let mut workspace = $workspace::new(Execution::portable())?;
            let mut output = [0xa5; $width];
            assert_eq!($probe(&mut workspace, &[0xa6; 256], &mut output), 0);
            assert_eq!(output, [0; $width]);
            let secret = workspace.with(|mut state| {
                state.update(b"abc")?;
                state.finalize_secret(&mut output)
            })??;
            assert_eq!(
                secret.digest.expose(),
                brynja_hash_sha2::$reference(b"abc")
                    .map_err(|_| Error::Failed)?
                    .as_bytes()
            );
            assert_eq!(secret.report.route, Route::Portable);
            drop(secret);
            assert_eq!(output, [0; $width]);
            #[cfg(feature = "hosted")]
            {
                use brynja_crypto_cpu_std::execution as host;
                let kernel = match (cfg!(target_arch = "aarch64"), $wide) {
                    (false, false) => host::Kernel::X86Sha256,
                    (false, true) => host::Kernel::X86Sha512,
                    (true, false) => host::Kernel::ArmSha256,
                    (true, true) => host::Kernel::ArmSha512,
                };
                let selected = host::Authority::new(kernel, host::Mode::Require);
                if std::env::var_os("BRYNJA_REQUIRE_SCOPED_SHA2_HOSTED").is_some() {
                    assert!(selected.is_ok(), "required hosted scoped SHA-2 kernel");
                }
                match selected {
                    Ok(owner) => {
                        let session = owner
                            .session()
                            .map_err(|_| Error::Failed)?
                            .ok_or(Error::Failed)?;
                        let mut workspace = $workspace::new(Execution::from_runtime(session)?)?;
                        assert_eq!($probe(&mut workspace, &[0xa6; 256], &mut output), 0);
                        let secret = workspace.with(|mut state| {
                            state.update(b"abc")?;
                            state.finalize_secret(&mut output)
                        })??;
                        assert_eq!(
                            secret.digest.expose(),
                            brynja_hash_sha2::$reference(b"abc")
                                .map_err(|_| Error::Failed)?
                                .as_bytes()
                        );
                        assert_eq!(secret.report.route, Route::Runtime(kernel));
                        drop(secret);
                        assert_eq!(output, [0; $width]);
                        workspace.with(|mut state| {
                            state.update(b"confidential")?;
                            owner.quarantine();
                            output.fill(0xa5);
                            assert!(matches!(
                                state.finalize_secret(&mut output),
                                Err(Error::Backend(_))
                            ));
                            Ok::<(), Error>(())
                        })??;
                        assert_eq!(output, [0; $width]);
                        let mut invoked = false;
                        assert!(matches!(
                            workspace.with(|_| invoked = true),
                            Err(Error::Backend(_))
                        ));
                        assert!(!invoked);
                    }
                    Err(host::Error::Unavailable(_)) => {}
                    Err(_) => return Err(Error::Failed),
                }
            }
        }};
    }

    #[test]
    fn named_portable_and_available_hosted_routes() -> Result<(), Error> {
        check!(Sha224Workspace, sha224, 28, execution224, false);
        check!(Sha256Workspace, sha256, 32, execution256, false);
        check!(Sha384Workspace, sha384, 48, execution384, true);
        check!(Sha512Workspace, sha512, 64, execution512, true);
        check!(Sha512_224Workspace, sha512_224, 28, execution512_224, true);
        check!(Sha512_256Workspace, sha512_256, 32, execution512_256, true);
        Ok(())
    }
}
