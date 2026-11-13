use super::*;

fn model(health: Health, generation: u64) -> Authority {
    Authority {
        kernel: Kernel::X86AesNi,
        admission: Admission::Static,
        dit: false,
        health: Cell::new(health),
        generation: Cell::new(generation),
        local: PhantomData,
    }
}

fn rejected(session: &Session<'_>, error: Error) {
    let mut state = [0x5a; 16];
    assert_eq!(session.encrypt128(&mut state, &[0; 176]), Err(error));
    assert_eq!(session.decrypt128(&mut state, &[0; 176]), Err(error));
    assert_eq!(session.encrypt192(&mut state, &[0; 208]), Err(error));
    assert_eq!(session.decrypt192(&mut state, &[0; 208]), Err(error));
    assert_eq!(session.encrypt256(&mut state, &[0; 240]), Err(error));
    assert_eq!(session.decrypt256(&mut state, &[0; 240]), Err(error));
    assert_eq!(state, [0x5a; 16]);
    let mut narrow = [0x5a; 176];
    let mut medium = [0x5a; 208];
    let mut wide = [0x5a; 240];
    assert_eq!(session.expand128(&[0; 16], &mut narrow), Err(error));
    assert_eq!(session.expand192(&[0; 24], &mut medium), Err(error));
    assert_eq!(session.expand256(&[0; 32], &mut wide), Err(error));
    assert_eq!(narrow, [0x5a; 176]);
    assert_eq!(medium, [0x5a; 208]);
    assert_eq!(wide, [0x5a; 240]);
}

#[test]
fn exact_static_bundle_checked_before_startup() {
    for kernel in [Kernel::X86AesNi, Kernel::ArmAes, Kernel::RiscVScalarAes] {
        // Evidence classification is not inferred from successful self-tests or
        // lost on failure. Exercise real reports in every lifecycle state.
        let mut observed = model(Health::Testing, 1);
        observed.kernel = kernel;
        let evidence_only = kernel == Kernel::RiscVScalarAes;
        assert_eq!(observed.report().evidence_only(), evidence_only);
        observed.complete_startup(true);
        assert_eq!(observed.report().evidence_only(), evidence_only);
        observed.quarantine();
        assert_eq!(observed.report().evidence_only(), evidence_only);
        let mut failed = model(Health::Testing, 1);
        failed.kernel = kernel;
        failed.complete_startup(false);
        assert_eq!(failed.report().evidence_only(), evidence_only);
        let (arch, features) = match kernel {
            Kernel::X86AesNi => (
                cfg!(target_arch = "x86_64"),
                cfg!(all(target_feature = "aes", target_feature = "sse2")),
            ),
            Kernel::ArmAes => (
                cfg!(all(target_arch = "aarch64", target_endian = "little")),
                cfg!(all(target_feature = "aes", target_feature = "neon")),
            ),
            Kernel::RiscVScalarAes => (
                cfg!(all(target_arch = "riscv64", target_endian = "little")),
                cfg!(all(target_feature = "zkne", target_feature = "zknd")),
            ),
        };
        let expected = if !arch {
            Err(Error::WrongArchitecture)
        } else if kernel == Kernel::RiscVScalarAes && !cfg!(brynja_cpu_evidence) {
            Err(Error::Unadmitted)
        } else if !features {
            Err(Error::MissingTargetFeatures)
        } else {
            Ok(())
        };
        assert_eq!(kernel.check_compiled_target(), expected);
        if let Err(error) = expected {
            assert_eq!(Authority::new(kernel).err(), Some(error));
            let mut owner = model(Health::Healthy, 2);
            owner.kernel = kernel;
            rejected(
                &Session {
                    owner: &owner,
                    generation: 2,
                },
                error,
            );
        }
    }
    assert_eq!(static_dit_policy_is_the_admitted_owner_setting(), Ok(()));
    #[cfg(all(
        feature = "aes-runtime-execution",
        target_arch = "riscv64",
        target_endian = "little",
        not(brynja_cpu_evidence)
    ))]
    {
        // Even an unsafe platform attestation cannot bypass ordinary-build
        // candidate exclusion. Rejection precedes any unsupported instruction.
        #[allow(unsafe_code)]
        unsafe {
            assert_eq!(
                Authority::from_platform(Kernel::RiscVScalarAes).err(),
                Some(Error::Unadmitted)
            );
            for policy in [DitPolicy::IfAvailable, DitPolicy::Require] {
                assert_eq!(
                    Authority::from_platform_with_dit(Kernel::RiscVScalarAes, policy, true).err(),
                    Some(Error::Unadmitted)
                );
            }
        }
    }
}

fn static_dit_policy_is_the_admitted_owner_setting() -> Result<(), Error> {
    for kernel in [Kernel::X86AesNi, Kernel::ArmAes, Kernel::RiscVScalarAes] {
        for policy in [DitPolicy::IfAvailable, DitPolicy::Require] {
            let available = kernel == Kernel::ArmAes && cfg!(target_feature = "dit");
            let expected = kernel
                .check_compiled_target()
                .and_then(|()| dit::admit(policy, available));
            match expected {
                Ok(enabled) => {
                    let owner = Authority::new_with_dit(kernel, policy)?;
                    assert_eq!(owner.dit_enabled(), enabled);
                    assert_eq!(owner.report().health, Health::Healthy);
                    assert_eq!(
                        owner.report().evidence_only(),
                        kernel == Kernel::RiscVScalarAes
                    );
                }
                Err(error) => {
                    assert_eq!(Authority::new_with_dit(kernel, policy).err(), Some(error));
                }
            }
        }
    }
    Ok(())
}

#[test]
fn testing_cannot_issue_or_execute_a_permit() {
    let owner = model(Health::Testing, 1);
    assert_eq!(owner.session().err(), Some(Error::NotReady));
    rejected(
        &Session {
            owner: &owner,
            generation: 1,
        },
        Error::NotReady,
    );
}

#[test]
fn failed_startup_is_terminal() {
    let owner = model(Health::Testing, 1);
    owner.complete_startup(false);
    assert_eq!(owner.report().health, Health::Quarantined);
    assert_eq!(owner.session().err(), Some(Error::Quarantined));
    rejected(
        &Session {
            owner: &owner,
            generation: 2,
        },
        Error::Quarantined,
    );
}

#[test]
fn stale_generation_never_mutates_state() {
    let owner = model(Health::Healthy, 2);
    rejected(
        &Session {
            owner: &owner,
            generation: 1,
        },
        Error::StaleGeneration,
    );
}

#[test]
fn revocation_is_shared_permanent_and_idempotent() {
    let owner = model(Health::Healthy, 2);
    let first = Session {
        owner: &owner,
        generation: 2,
    };
    let second = Session {
        owner: &owner,
        generation: 2,
    };
    first.quarantine();
    second.quarantine();
    assert_eq!(owner.report().generation, 3);
    rejected(&first, Error::Quarantined);
    rejected(&second, Error::Quarantined);
    assert_eq!(owner.session().err(), Some(Error::Quarantined));
}

#[test]
fn incomplete_operation_and_unwind_revoke_owner() {
    for (health, generation, expected) in [
        (Health::Testing, 2, Error::NotReady),
        (Health::Quarantined, 3, Error::Quarantined),
        (Health::Healthy, 3, Error::StaleGeneration),
    ] {
        let owner = model(Health::Healthy, 2);
        let session = Session {
            owner: &owner,
            generation: 2,
        };
        let operation = Operation {
            session: &session,
            completed: false,
        };
        // Simulate a lifecycle change after entry but before successful return.
        // This calls the production completion path shared by both operations.
        owner.health.set(health);
        owner.generation.set(generation);
        assert_eq!(operation.complete(), Err(expected));
        assert_eq!(owner.report().health, Health::Quarantined);
        rejected(&session, Error::Quarantined);
    }
    let owner = model(Health::Healthy, 2);
    let session = Session {
        owner: &owner,
        generation: 2,
    };
    drop(Operation {
        session: &session,
        completed: false,
    });
    rejected(&session, Error::Quarantined);
    let owner = model(Health::Healthy, 2);
    let session = Session {
        owner: &owner,
        generation: 2,
    };
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = Operation {
            session: &session,
            completed: false,
        };
        std::panic::resume_unwind(std::boxed::Box::new(()));
    }));
    assert!(outcome.is_err());
    rejected(&session, Error::Quarantined);
}

#[cfg(any(
    all(
        brynja_cpu_evidence,
        target_arch = "riscv64",
        target_endian = "little",
        target_feature = "zkne",
        target_feature = "zknd"
    ),
    all(
        target_arch = "x86_64",
        target_feature = "aes",
        target_feature = "sse2"
    ),
    all(
        target_arch = "aarch64",
        target_endian = "little",
        target_feature = "aes",
        target_feature = "neon"
    )
))]
mod native {
    use super::*;
    fn kernel() -> Kernel {
        if cfg!(target_arch = "x86_64") {
            Kernel::X86AesNi
        } else if cfg!(target_arch = "riscv64") {
            Kernel::RiscVScalarAes
        } else {
            Kernel::ArmAes
        }
    }
    fn flat<const N: usize, const S: usize>(keys: &[[u8; 16]; N]) -> [u8; S] {
        let mut bytes = [0; S];
        for (key, slot) in keys.iter().zip(bytes.as_chunks_mut::<16>().0) {
            slot.copy_from_slice(key);
        }
        bytes
    }

    #[test]
    fn startup_tests_all_widths_and_both_directions() -> Result<(), Error> {
        let owner = Authority::new(kernel())?;
        assert_eq!(owner.report().health, Health::Healthy);
        assert_eq!(owner.report().generation, 2);
        let session = owner.session()?;
        let mut schedule128 = [0xa5; 176];
        let mut schedule192 = [0xa5; 208];
        let mut schedule256 = [0xa5; 240];
        session.expand128(
            kat::KEYS128
                .as_flattened()
                .first_chunk()
                .ok_or(Error::InternalDomain)?,
            &mut schedule128,
        )?;
        session.expand192(
            kat::KEYS192
                .as_flattened()
                .first_chunk()
                .ok_or(Error::InternalDomain)?,
            &mut schedule192,
        )?;
        session.expand256(
            kat::KEYS256
                .as_flattened()
                .first_chunk()
                .ok_or(Error::InternalDomain)?,
            &mut schedule256,
        )?;
        assert_eq!(schedule128, flat::<11, 176>(&kat::KEYS128));
        assert_eq!(schedule192, flat::<13, 208>(&kat::KEYS192));
        assert_eq!(schedule256, flat::<15, 240>(&kat::KEYS256));
        let mut state = kat::PLAIN;
        session.encrypt128(&mut state, &flat::<11, 176>(&kat::KEYS128))?;
        assert_eq!(state, kat::CIPHER128);
        session.decrypt128(&mut state, &flat::<11, 176>(&kat::KEYS128))?;
        assert_eq!(state, kat::PLAIN);
        session.encrypt192(&mut state, &flat::<13, 208>(&kat::KEYS192))?;
        assert_eq!(state, kat::CIPHER192);
        session.decrypt192(&mut state, &flat::<13, 208>(&kat::KEYS192))?;
        assert_eq!(state, kat::PLAIN);
        session.encrypt256(&mut state, &flat::<15, 240>(&kat::KEYS256))?;
        assert_eq!(state, kat::CIPHER256);
        session.decrypt256(&mut state, &flat::<15, 240>(&kat::KEYS256))?;
        assert_eq!(state, kat::PLAIN);
        Ok(())
    }

    #[test]
    fn domain_failure_revokes_without_fallback() -> Result<(), Error> {
        let owner = Authority::new(kernel())?;
        let session = owner.session()?;
        let mut state = kat::PLAIN;
        // Private parameter mismatch cannot be expressed by the public methods.
        assert_eq!(
            session.transform::<176, 13>(&mut state, &[0; 176], false),
            Err(Error::InternalDomain)
        );
        assert_eq!(state, kat::PLAIN);
        rejected(&session, Error::Quarantined);
        Ok(())
    }

    #[test]
    fn startup_rejects_every_schedule_byte_mismatch() -> Result<(), Error> {
        fn check<const K: usize, const S: usize>(
            owner: &Authority,
            expected: [u8; S],
        ) -> Result<(), Error> {
            assert!(kat::expansion_answer::<K, S>(owner, &expected));
            for i in 0..S {
                let mut corrupt = expected;
                *corrupt.get_mut(i).ok_or(Error::InternalDomain)? ^= 1;
                assert!(!kat::expansion_answer::<K, S>(owner, &corrupt));
            }
            assert!(!kat::expansion_answer::<K, S>(owner, &[]));
            Ok(())
        }
        let owner = Authority::new(kernel())?;
        check::<16, 176>(&owner, flat::<11, 176>(&kat::KEYS128))?;
        check::<24, 208>(&owner, flat::<13, 208>(&kat::KEYS192))?;
        check::<32, 240>(&owner, flat::<15, 240>(&kat::KEYS256))?;
        let mut corrupt = flat::<11, 176>(&kat::KEYS128);
        corrupt[175] ^= 1;
        owner.complete_startup(kat::expansion_answer::<16, 176>(&owner, &corrupt));
        assert_eq!(owner.session().err(), Some(Error::Quarantined));
        std::println!("AES_EXPANSION_STARTUP_PASS: 624 mismatches rejected");
        Ok(())
    }
}
