use super::*;

fn model() -> Authority {
    Authority {
        kernel: if cfg!(target_arch = "aarch64") {
            Kernel::ArmSha256
        } else {
            Kernel::X86Sha256
        },
        health: Cell::new(Health::Testing),
        generation: Cell::new(1),
        thread_bound: PhantomData,
    }
}

#[test]
fn testing_and_failed_startup_never_issue_sessions() {
    let owner = model();
    assert!(matches!(owner.session(), Err(Error::NotReady)));
    owner.complete_startup(false);
    assert_eq!(owner.report().generation, 2);
    assert!(matches!(owner.session(), Err(Error::Quarantined)));
    owner.quarantine();
    assert_eq!(owner.report().generation, 2);
}

#[test]
fn stale_generation_rejects_before_operation() {
    let owner = model();
    owner.complete_startup(true);
    let stale = Session {
        owner: &owner,
        generation: 1,
    };
    let mut state = [0x55; 8];
    assert_eq!(
        stale.compress_sha256(PublicData::new(&mut state), PublicData::new(&[0; 64])),
        Err(Error::StaleGeneration)
    );
    assert_eq!(state, [0x55; 8]);
}

#[test]
fn quarantine_invalidates_existing_sessions_before_mutation() {
    let owner = model();
    owner.complete_startup(true);
    let session = Session {
        owner: &owner,
        generation: 2,
    };
    owner.quarantine();
    owner.quarantine();
    assert_eq!(owner.report().generation, 3);
    assert_eq!(session.report().health, Health::Quarantined);
    let mut state32 = [13; 8];
    let mut state64 = [17; 8];
    let mut lanes = [19; 25];
    assert_eq!(
        session.compress_sha256(PublicData::new(&mut state32), PublicData::new(&[0; 64])),
        Err(Error::Quarantined)
    );
    assert_eq!(
        session.compress_sha512(PublicData::new(&mut state64), PublicData::new(&[0; 128])),
        Err(Error::Quarantined)
    );
    assert_eq!(
        session.permute_keccak(PublicData::new(&mut lanes)),
        Err(Error::Quarantined)
    );
    assert_eq!(state32, [13; 8]);
    assert_eq!(state64, [17; 8]);
    assert_eq!(lanes, [19; 25]);
}

#[test]
fn exact_architecture_inventory() {
    for kernel in Kernel::ALL {
        let x86 = matches!(
            kernel,
            Kernel::X86Sha256 | Kernel::X86Sha512 | Kernel::X86Keccak
        );
        let expected =
            (x86 && cfg!(target_arch = "x86_64")) || (!x86 && cfg!(target_arch = "aarch64"));
        assert_eq!(operations::architecture(kernel).is_ok(), expected);
    }
}

#[test]
fn dedicated_sha512_runtime_dispatch_and_revocation() -> Result<(), Error> {
    if Kernel::X86Sha512.check_compiled_target().is_err() {
        assert!(std::env::var_os("BRYNJA_REQUIRE_X86_SHA512").is_none());
        return Ok(());
    }
    // Test-only authority on the explicitly specialized SDE/native lane.
    // This does not claim that CPUID alone establishes platform authority.
    let mut owner = model();
    owner.kernel = Kernel::X86Sha512;
    owner.complete_startup(operations::known_answer(owner.kernel));
    assert_eq!(owner.report().health, Health::Healthy);
    let session = owner.session()?;
    let mut state = crate::sha512::initial_state();
    session.compress_sha512(
        PublicData::new(&mut state),
        PublicData::new(&crate::sha512::abc_block()),
    )?;
    assert_eq!(state, crate::sha512::abc_digest_state());
    let mut narrow = [0xa5; 8];
    assert_eq!(
        session.compress_sha256(PublicData::new(&mut narrow), PublicData::new(&[0; 64])),
        Err(Error::WrongOperation)
    );
    assert_eq!(narrow, [0xa5; 8]);
    #[cfg(feature = "hardened-execution")]
    {
        let mut hardened = crate::hardened_execution::Session::from_runtime(owner.session()?)?;
        let mut secret = [0_u8; 64];
        for (slot, word) in secret
            .chunks_exact_mut(8)
            .zip(crate::sha512::initial_state())
        {
            slot.copy_from_slice(&word.to_be_bytes());
        }
        hardened.compress(true, &mut secret, &crate::sha512::abc_block())?;
        for (slot, word) in secret.chunks_exact(8).zip(state) {
            assert_eq!(slot, word.to_be_bytes());
        }
        owner.quarantine();
        let before = secret;
        assert_eq!(
            hardened.compress(true, &mut secret, &[0; 128]),
            Err(Error::Quarantined)
        );
        assert_eq!(secret, before);
    }
    owner.quarantine();
    let before = state;
    assert_eq!(
        session.compress_sha512(PublicData::new(&mut state), PublicData::new(&[0; 128])),
        Err(Error::Quarantined)
    );
    assert_eq!(state, before);
    std::println!("DEDICATED_X86_SHA512_RUNTIME: KAT; exact identity; revocation=PASS");
    Ok(())
}
