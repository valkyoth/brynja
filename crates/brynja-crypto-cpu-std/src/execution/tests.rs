use super::*;

#[test]
fn mode_matrix_is_explicit_and_fail_closed() {
    for reason in [
        Unavailable::WrongArchitecture,
        Unavailable::MissingFeaturesOrOsState,
        Unavailable::MissingMigrationGuarantee,
    ] {
        assert_eq!(
            choose(Mode::Portable, Err(reason)),
            Ok(Route::PortableRequested)
        );
        assert_eq!(
            choose(Mode::Prefer, Err(reason)),
            Ok(Route::PortableFallback(reason))
        );
        assert_eq!(
            choose(Mode::Require, Err(reason)),
            Err(Error::Unavailable(reason))
        );
    }
    assert_eq!(choose(Mode::Portable, Ok(())), Ok(Route::PortableRequested));
    assert_eq!(choose(Mode::Prefer, Ok(())), Ok(Route::Accelerated));
    assert_eq!(choose(Mode::Require, Ok(())), Ok(Route::Accelerated));
}

#[test]
fn portable_never_probes_or_has_an_owner() -> Result<(), Error> {
    for kernel in Kernel::ALL {
        let owner = Authority::new(kernel, Mode::Portable)?;
        assert_eq!(
            owner.report(),
            Report {
                kernel,
                route: Route::PortableRequested,
                health: None
            }
        );
        assert!(owner.session()?.is_none());
        owner.quarantine();
        assert_eq!(owner.report().route, Route::PortableRequested);
    }
    Ok(())
}

#[test]
fn real_platform_selection_and_direct_operations() -> Result<(), Error> {
    let mut accelerated = 0;
    for kernel in Kernel::ALL {
        let owner = Authority::new(kernel, Mode::Prefer)?;
        match owner.report().route {
            Route::PortableFallback(reason) => {
                assert!(owner.session()?.is_none());
                assert!(matches!(Authority::new(kernel, Mode::Require),
                    Err(Error::Unavailable(value)) if value == reason));
            }
            Route::Accelerated => {
                accelerated += 1;
                assert_eq!(owner.report().health, Some(Health::Healthy));
                let session = owner
                    .session()?
                    .ok_or(Error::Kernel(KernelError::NotReady))?;
                exercise(&session, kernel)?;
                owner.quarantine();
                assert_eq!(owner.report().health, Some(Health::Quarantined));
                let mut untouched = [19; 25];
                assert_eq!(
                    session.permute_keccak(&mut untouched),
                    Err(KernelError::Quarantined)
                );
                assert_eq!(untouched, [19; 25]);
                assert!(matches!(
                    owner.session(),
                    Err(Error::Kernel(KernelError::Quarantined))
                ));
                // Re-selection is a new owner, not renewal of an old permit.
                let fresh = Authority::new(kernel, Mode::Require)?;
                assert_eq!(fresh.report().health, Some(Health::Healthy));
                assert_eq!(owner.report().health, Some(Health::Quarantined));
            }
            Route::PortableRequested => return Err(Error::Kernel(KernelError::NotReady)),
        }
    }
    if cfg!(target_arch = "x86_64") {
        assert_eq!(accelerated, 0);
    }
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
        assert_eq!(
            accelerated, expected,
            "supported platform routes must execute"
        );
    }
    Ok(())
}

fn exercise(session: &Session<'_>, kernel: Kernel) -> Result<(), Error> {
    match kernel {
        Kernel::ArmSha256 | Kernel::X86Sha256 => {
            let mut state = [
                0x6a09_e667,
                0xbb67_ae85,
                0x3c6e_f372,
                0xa54f_f53a,
                0x510e_527f,
                0x9b05_688c,
                0x1f83_d9ab,
                0x5be0_cd19,
            ];
            let mut block = [0; 64];
            block[..4].copy_from_slice(&[b'a', b'b', b'c', 0x80]);
            block[63] = 24;
            session
                .compress_sha256(&mut state, &block)
                .map_err(Error::Kernel)?;
            assert_eq!(
                state,
                [
                    0xba78_16bf,
                    0x8f01_cfea,
                    0x4141_40de,
                    0x5dae_2223,
                    0xb003_61a3,
                    0x9617_7a9c,
                    0xb410_ff61,
                    0xf200_15ad
                ]
            );
        }
        Kernel::ArmSha512 => {
            let mut state = [
                0x6a09_e667_f3bc_c908,
                0xbb67_ae85_84ca_a73b,
                0x3c6e_f372_fe94_f82b,
                0xa54f_f53a_5f1d_36f1,
                0x510e_527f_ade6_82d1,
                0x9b05_688c_2b3e_6c1f,
                0x1f83_d9ab_fb41_bd6b,
                0x5be0_cd19_137e_2179,
            ];
            let mut block = [0; 128];
            block[..4].copy_from_slice(&[b'a', b'b', b'c', 0x80]);
            block[127] = 24;
            session
                .compress_sha512(&mut state, &block)
                .map_err(Error::Kernel)?;
            assert_eq!(
                state,
                [
                    0xddaf_35a1_9361_7aba,
                    0xcc41_7349_ae20_4131,
                    0x12e6_fa4e_89a9_7ea2,
                    0x0a9e_eee6_4b55_d39a,
                    0x2192_992a_274f_c1a8,
                    0x36ba_3c23_a3fe_ebbd,
                    0x454d_4423_643c_e80e,
                    0x2a9a_c94f_a54c_a49f
                ]
            );
        }
        Kernel::ArmKeccak | Kernel::X86Keccak => {
            let mut state = [0; 25];
            session.permute_keccak(&mut state).map_err(Error::Kernel)?;
            assert_eq!(state[0], 0xf125_8f79_40e1_dde7);
            assert_eq!(state[24], 0xeaf1_ff7b_5cec_a249);
        }
        _ => return Err(Error::Kernel(KernelError::WrongOperation)),
    }
    let mut state = [31; 8];
    if kernel != Kernel::ArmSha512 {
        assert_eq!(
            session.compress_sha512(&mut state, &[0; 128]),
            Err(KernelError::WrongOperation)
        );
        assert_eq!(state, [31; 8]);
    }
    Ok(())
}
