use super::{Authority, Error, Health, Kernel, Session};

#[test]
fn static_authority_rejects_incomplete_bundles_before_startup() {
    for kernel in Kernel::ALL {
        let (arch, features) = match kernel {
            Kernel::X86Sha256 => (
                cfg!(target_arch = "x86_64"),
                cfg!(all(target_feature = "sha", target_feature = "sse2")),
            ),
            Kernel::X86Keccak => (
                cfg!(target_arch = "x86_64"),
                cfg!(all(target_feature = "avx", target_feature = "avx2")),
            ),
            Kernel::ArmSha256 => (
                cfg!(target_arch = "aarch64"),
                cfg!(all(target_feature = "neon", target_feature = "sha2")),
            ),
            Kernel::ArmSha512 | Kernel::ArmKeccak => (
                cfg!(target_arch = "aarch64"),
                cfg!(all(target_feature = "neon", target_feature = "sha3")),
            ),
        };
        let expected = if !arch {
            Err(Error::WrongArchitecture)
        } else if !features {
            Err(Error::MissingTargetFeatures)
        } else {
            Ok(())
        };
        // Check metadata independently before a mutated gate could enter code.
        assert_eq!(kernel.check_compiled_target(), expected);
        if let Err(expected) = expected {
            assert_eq!(Authority::new(kernel).err(), Some(expected));
        }
    }
}

#[test]
fn static_authority_real_kats_and_operations() -> Result<(), Error> {
    for kernel in Kernel::ALL {
        if kernel.check_compiled_target().is_err() {
            continue;
        }
        let owner = Authority::new(kernel)?;
        assert_eq!(owner.report().health, Health::Healthy);
        assert_eq!(owner.report().generation, 2);
        let session = owner.session()?;
        match kernel {
            Kernel::X86Sha256 | Kernel::ArmSha256 => {
                let mut state = crate::sha256::initial_state();
                session.compress_sha256(&mut state, &crate::sha256::abc_block())?;
                assert_eq!(state, crate::sha256::abc_digest_state());
                let mut wrong = [42; 25];
                assert_eq!(
                    session.permute_keccak(&mut wrong),
                    Err(Error::WrongOperation)
                );
                assert_eq!(wrong, [42; 25]);
            }
            Kernel::ArmSha512 => {
                let mut state = crate::sha512::initial_state();
                session.compress_sha512(&mut state, &crate::sha512::abc_block())?;
                assert_eq!(state, crate::sha512::abc_digest_state());
                let mut wrong = [42; 8];
                assert_eq!(
                    session.compress_sha256(&mut wrong, &[0; 64]),
                    Err(Error::WrongOperation)
                );
                assert_eq!(wrong, [42; 8]);
            }
            Kernel::X86Keccak | Kernel::ArmKeccak => {
                let mut state = [0; 25];
                session.permute_keccak(&mut state)?;
                assert_eq!(state, crate::keccak_constants::ZERO_STATE_RESULT);
                let mut wrong = [42; 8];
                assert_eq!(
                    session.compress_sha512(&mut wrong, &[0; 128]),
                    Err(Error::WrongOperation)
                );
                assert_eq!(wrong, [42; 8]);
            }
        }
        let stale = Session {
            owner: &owner,
            generation: 1,
        };
        assert_eq!(
            stale.permute_keccak(&mut [0; 25]),
            Err(Error::StaleGeneration)
        );
        owner.quarantine();
        assert_eq!(owner.report().generation, 3);
        owner.quarantine();
        assert_eq!(owner.report().generation, 3);
        assert_eq!(owner.session().err(), Some(Error::Quarantined));
        rejected_outputs(&session, Error::Quarantined);
    }
    Ok(())
}

fn rejected_outputs(session: &Session<'_>, expected: Error) {
    let mut small = [42; 8];
    let mut large = [42; 8];
    let mut lanes = [42; 25];
    assert_eq!(session.compress_sha256(&mut small, &[0; 64]), Err(expected));
    assert_eq!(
        session.compress_sha512(&mut large, &[0; 128]),
        Err(expected)
    );
    assert_eq!(session.permute_keccak(&mut lanes), Err(expected));
    assert_eq!(small, [42; 8]);
    assert_eq!(large, [42; 8]);
    assert_eq!(lanes, [42; 25]);
}

#[test]
fn static_authority_failed_startup_never_issues_session() {
    // Lifecycle-only model: does not enter a kernel or grant public authority.
    let owner = Authority {
        kernel: Kernel::X86Sha256,
        health: core::cell::Cell::new(Health::Testing),
        generation: core::cell::Cell::new(1),
        thread_bound: core::marker::PhantomData,
    };
    assert_eq!(owner.session().err(), Some(Error::NotReady));
    owner.complete_startup(false);
    assert_eq!(owner.report().health, Health::Quarantined);
    assert_eq!(owner.session().err(), Some(Error::Quarantined));
    rejected_outputs(
        &Session {
            owner: &owner,
            generation: 2,
        },
        Error::Quarantined,
    );
    owner.quarantine();
    assert_eq!(owner.report().generation, 2);
}

#[test]
fn static_authority_stale_generation_precedes_instruction_entry() {
    let owner = Authority {
        kernel: Kernel::X86Sha256,
        health: core::cell::Cell::new(Health::Healthy),
        generation: core::cell::Cell::new(2),
        thread_bound: core::marker::PhantomData,
    };
    let stale = Session {
        owner: &owner,
        generation: 1,
    };
    let mut small = [42; 8];
    let mut large = [42; 8];
    let mut lanes = [42; 25];
    assert_eq!(
        stale.compress_sha256(&mut small, &[0; 64]),
        Err(Error::StaleGeneration)
    );
    assert_eq!(
        stale.compress_sha512(&mut large, &[0; 128]),
        Err(Error::StaleGeneration)
    );
    assert_eq!(
        stale.permute_keccak(&mut lanes),
        Err(Error::StaleGeneration)
    );
    assert_eq!(small, [42; 8]);
    assert_eq!(large, [42; 8]);
    assert_eq!(lanes, [42; 25]);
}

#[test]
fn static_authority_testing_is_distinct_and_never_mutates_outputs() {
    // Private lifecycle models only: neither state permits kernel entry.
    for kernel in Kernel::ALL {
        for (health, expected) in [
            (Health::Testing, Error::NotReady),
            (Health::Quarantined, Error::Quarantined),
        ] {
            let owner = Authority {
                kernel,
                health: core::cell::Cell::new(health),
                generation: core::cell::Cell::new(1),
                thread_bound: core::marker::PhantomData,
            };
            assert_eq!(owner.session().err(), Some(expected));
            for generation in [0, 1, 2, 3, u64::MAX] {
                rejected_outputs(
                    &Session {
                        owner: &owner,
                        generation,
                    },
                    expected,
                );
                assert_eq!(owner.report().health, health);
                assert_eq!(owner.report().generation, 1);
            }
        }
    }
}
