//! General-t scoped engine borrowing and packaged-consumer checks.
use super::*;

/// Checks a 9-bit output without moving the active engine or scratch.
#[inline(never)]
pub extern "C" fn execution_general(
    workspace: &mut Sha512TWorkspace<'_>,
    input: &[u8; 256],
    output: &mut [u8; 2],
) -> u8 {
    let result = workspace.with(|mut state| {
        state.update(input)?;
        drop(state.finalize_secret(output)?);
        Ok::<(), Error>(())
    });
    u8::from(!matches!(result, Ok(Ok(()))))
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use brynja_hash_sha2::{
        Sha512TBits,
        hardened_execution::{Execution, Route},
    };

    fn campaign<'a>(
        mut execution: impl FnMut() -> Result<Execution<'a>, Error>,
        route: Route,
    ) -> Result<(), Error> {
        for t in (1..512).filter(|t| *t != 384) {
            let p = Sha512TBits::new(t).map_err(|_| Error::Failed)?;
            let mut workspace = Sha512TWorkspace::new(p, execution()?)?;
            if t == 9 {
                let mut bytes = [0xa5; 2];
                assert_eq!(
                    execution_general(&mut workspace, &[0xa6; 256], &mut bytes),
                    0
                );
                assert_eq!(bytes, [0; 2]);
            }
            let mut output = std::vec![0xa5; p.output_bytes()];
            let secret = workspace.with(|mut state| {
                state.update(b"abc")?;
                state.finalize_secret(&mut output)
            })??;
            assert_eq!(secret.digest.parameter(), p);
            assert_eq!(
                secret.digest.as_bytes(),
                brynja_hash_sha2::sha512_t(p, b"abc")
                    .map_err(|_| Error::Failed)?
                    .as_bytes()
            );
            assert_eq!(secret.report.route, route);
            assert_eq!(secret.report.portable_iv_blocks, 1);
            drop(secret);
            assert!(output.iter().all(|b| *b == 0));
        }
        Ok(())
    }

    #[test]
    fn general_portable_and_available_hosted_routes() -> Result<(), Error> {
        campaign(|| Ok(Execution::portable()), Route::Portable)?;
        #[cfg(feature = "hosted")]
        {
            use brynja_crypto_cpu_std::execution as host;
            let kernel = if cfg!(target_arch = "aarch64") {
                host::Kernel::ArmSha512
            } else {
                host::Kernel::X86Sha512
            };
            let selected = host::Authority::new(kernel, host::Mode::Require);
            if std::env::var_os("BRYNJA_REQUIRE_SCOPED_SHA2_HOSTED").is_some() {
                assert!(selected.is_ok(), "required hosted general-t kernel");
            }
            match selected {
                Ok(owner) => {
                    let execution = || {
                        Execution::from_runtime(
                            owner
                                .session()
                                .map_err(|_| Error::Failed)?
                                .ok_or(Error::Failed)?,
                        )
                    };
                    campaign(execution, Route::Runtime(kernel))?;
                    let p = Sha512TBits::new(9).map_err(|_| Error::Failed)?;
                    let mut workspace = Sha512TWorkspace::new(p, execution()?)?;
                    let mut output = [0xa5; 2];
                    workspace.with(|mut state| {
                        state.update(b"secret")?;
                        owner.quarantine();
                        assert!(matches!(
                            state.finalize_secret(&mut output),
                            Err(Error::Backend(_))
                        ));
                        Ok::<(), Error>(())
                    })??;
                    assert_eq!(output, [0; 2]);
                    let mut called = false;
                    assert!(matches!(
                        workspace.with(|_| called = true),
                        Err(Error::Backend(_))
                    ));
                    assert!(!called);
                }
                Err(host::Error::Unavailable(_)) => {}
                Err(_) => return Err(Error::Failed),
            }
        }
        Ok(())
    }
}
