//! Downstream ordinary hosted-authority acceptance; no evidence cfg or secret.
use brynja_crypto_cpu_std::execution::{
    Authority, Error, Health, Kernel, KernelError, Mode, PublicData, Route,
};

/// Exercises each available kernel owner and verifies quarantine is terminal.
pub fn validate() -> Result<usize, Error> {
    let mut count = 0;
    for kernel in Kernel::ALL {
        let portable = Authority::new(kernel, Mode::Portable)?;
        assert_eq!(portable.report().route, Route::PortableRequested);
        assert!(portable.session()?.is_none());
        let owner = Authority::new(kernel, Mode::Prefer)?;
        match owner.report().route {
            Route::PortableFallback(reason) => {
                assert!(owner.session()?.is_none());
                assert!(matches!(Authority::new(kernel, Mode::Require),
                    Err(Error::Unavailable(value)) if value == reason));
            }
            Route::Accelerated => {
                count += 1;
                assert_eq!(owner.report().health, Some(Health::Healthy));
                let session = owner
                    .session()?
                    .ok_or(Error::Kernel(KernelError::NotReady))?;
                // Startup already compares the complete exact KAT. Invoke the
                // operational method separately to catch no-op session routes.
                match kernel {
                    Kernel::X86Sha256 | Kernel::ArmSha256 => {
                        let mut state = [0; 8];
                        session
                            .compress_sha256(PublicData::new(&mut state), PublicData::new(&[0; 64]))
                            .map_err(Error::Kernel)?;
                        assert_ne!(state, [0; 8]);
                    }
                    Kernel::ArmSha512 => {
                        let mut state = [0; 8];
                        session
                            .compress_sha512(
                                PublicData::new(&mut state),
                                PublicData::new(&[0; 128]),
                            )
                            .map_err(Error::Kernel)?;
                        assert_ne!(state, [0; 8]);
                    }
                    Kernel::X86Keccak | Kernel::ArmKeccak => {
                        let mut state = [0; 25];
                        session
                            .permute_keccak(PublicData::new(&mut state))
                            .map_err(Error::Kernel)?;
                        assert_eq!(state[0], 0xf125_8f79_40e1_dde7);
                    }
                    _ => return Err(Error::Kernel(KernelError::WrongOperation)),
                }
                owner.quarantine();
                assert_eq!(owner.report().health, Some(Health::Quarantined));
                let mut state = [37; 25];
                assert_eq!(
                    session.permute_keccak(PublicData::new(&mut state)),
                    Err(KernelError::Quarantined)
                );
                assert_eq!(state, [37; 25]);
            }
            Route::PortableRequested => return Err(Error::Kernel(KernelError::NotReady)),
        }
    }
    Ok(count)
}

#[test]
fn downstream_runtime_selection() -> Result<(), Error> {
    let count = validate()?;
    #[cfg(all(
        target_arch = "aarch64",
        any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "windows"
        )
    ))]
    {
        let neon = std::arch::is_aarch64_feature_detected!("neon");
        let expected = usize::from(neon && std::arch::is_aarch64_feature_detected!("sha2"))
            + 2 * usize::from(neon && std::arch::is_aarch64_feature_detected!("sha3"));
        assert_eq!(count, expected);
    }
    #[cfg(not(target_arch = "aarch64"))]
    assert_eq!(count, 0);
    let _ = count;
    Ok(())
}
