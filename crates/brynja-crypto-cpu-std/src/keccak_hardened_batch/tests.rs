use super::*;
use brynja_crypto_cpu::keccak_hardened_batch::Error as CpuError;

#[test]
fn portable_does_not_call_detector_and_fallback_is_unavailability_only() -> Result<(), Error> {
    use core::sync::atomic::{AtomicBool, Ordering};
    static PROBED: AtomicBool = AtomicBool::new(false);
    fn forbidden() -> Result<CpuAuthority, Error> {
        PROBED.store(true, Ordering::Relaxed);
        Err(Error::Unavailable)
    }
    fn unavailable() -> Result<CpuAuthority, Error> {
        Err(Error::Unavailable)
    }
    fn kat_failure() -> Result<CpuAuthority, Error> {
        Err(backend(CpuError::Quarantined))
    }
    fn invariant() -> Result<CpuAuthority, Error> {
        Err(backend(CpuError::Invariant))
    }
    fn missing() -> Result<CpuAuthority, Error> {
        Err(backend(CpuError::MissingFeatures))
    }
    fn wrong() -> Result<CpuAuthority, Error> {
        Err(backend(CpuError::WrongArchitecture))
    }
    let owner = Authority::select(Mode::Portable, forbidden)?;
    assert!(!PROBED.load(Ordering::Relaxed));
    assert_eq!(owner.kernel()?, None);
    assert!(matches!(
        owner.executor(0),
        Err(Error::Execution(ExecutionError::InvalidSelection))
    ));
    assert!(owner.executor(1).is_ok());
    assert_eq!(
        Authority::select(Mode::Prefer, unavailable)?.kernel()?,
        None
    );
    assert!(matches!(
        Authority::select(Mode::Require, unavailable),
        Err(Error::Unavailable)
    ));
    for failure in [kat_failure, invariant, missing, wrong] {
        for mode in [Mode::Prefer, Mode::Require] {
            assert!(matches!(
                Authority::select(mode, failure),
                Err(Error::Execution(_))
            ));
        }
    }
    Ok(())
}

#[cfg(all(
    target_arch = "x86_64",
    not(all(target_feature = "avx", target_feature = "avx2"))
))]
#[test]
fn generic_x86_does_not_infer_migration_authority() -> Result<(), Error> {
    assert_eq!(Authority::new(Mode::Prefer)?.kernel()?, None);
    assert!(matches!(
        Authority::new(Mode::Require),
        Err(Error::Unavailable)
    ));
    Ok(())
}

#[test]
fn actual_hardened_routes_clear_outputs_and_never_recover_revoked_authority() -> Result<(), Error> {
    let message = [0xa5; 512]; // Public fixture, never logged as a secret.
    let bits =
        brynja_hash_sha3::Fips202BitString::new(&message, 8).map_err(|_| Error::Unavailable)?;
    let inputs: [Option<Input<'_>>; CAPACITY] =
        core::array::from_fn(|_| Input::new(Algorithm::Sha3_256, bits, 256).ok());
    assert!(inputs.iter().all(Option::is_some));
    let expected = brynja_hash_sha3::sha3_256(&message).map_err(|_| Error::Unavailable)?;
    for mode in [Mode::Portable, Mode::Prefer, Mode::Require] {
        let authority = match Authority::new(mode) {
            Ok(owner) => owner,
            Err(Error::Unavailable) if mode == Mode::Require => {
                assert!(
                    std::env::var_os("BRYNJA_REQUIRE_HOSTED_HARDENED_BATCH").is_none(),
                    "required native hosted kernel unavailable"
                );
                continue;
            }
            Err(error) => return Err(error),
        };
        let kernel = authority.kernel()?;
        let executor = authority.executor(1)?;
        let mut workspace = Workspace::new();
        let mut staging = [0xff; CAPACITY * 32 + 7];
        let mut outputs = [[0xff; 32]; CAPACITY];
        let mut cancelled = || false;
        // Routine budget exhaustion must clear outputs but preserve reuse.
        assert!(matches!(
            executor.digest_secret(
                &inputs,
                outputs.each_mut().map(|out| Some(out.as_mut_slice())),
                &mut workspace,
                &mut staging,
                &mut Control::new(0, &mut cancelled)
            ),
            Err(ExecutionError::WorkLimit)
        ));
        assert_eq!(outputs, [[0; 32]; CAPACITY]);
        let (secret, report) = executor
            .digest_secret(
                &inputs,
                outputs.each_mut().map(|out| Some(out.as_mut_slice())),
                &mut workspace,
                &mut staging,
                &mut Control::new(1000, &mut cancelled),
            )
            .map_err(Error::Execution)?;
        for index in 0..CAPACITY {
            assert_eq!(secret.expose(index), Some(expected.as_bytes().as_slice()));
        }
        assert_eq!(report.kernel, kernel);
        assert_eq!(report.vector_calls > 0, kernel.is_some());
        drop(secret);
        assert_eq!(outputs, [[0; 32]; CAPACITY]);
        assert_eq!(staging, [0; CAPACITY * 32 + 7]);
        if kernel.is_some() {
            authority.quarantine();
            assert!(authority.kernel().is_err());
            assert!(authority.executor(1).is_err());
        } else {
            // Portable owners hold no CPU authority; local revocation is explicit.
            executor.quarantine();
        }
        outputs.fill([0xa5; 32]);
        assert!(
            executor
                .digest_secret(
                    &inputs,
                    outputs.each_mut().map(|out| Some(out.as_mut_slice())),
                    &mut workspace,
                    &mut staging,
                    &mut Control::new(1000, &mut cancelled)
                )
                .is_err()
        );
        assert_eq!(outputs, [[0; 32]; CAPACITY]);
        outputs.fill([0xa5; 32]);
        assert!(
            executor
                .digest_public(
                    &inputs,
                    outputs.each_mut().map(|out| Some(out.as_mut_slice())),
                    &mut workspace,
                    &mut staging,
                    &mut Control::new(1000, &mut cancelled),
                    Sha3PublicDeclassification::acknowledge()
                )
                .is_err()
        );
        assert_eq!(outputs, [[0xa5; 32]; CAPACITY]);
    }
    Ok(())
}
