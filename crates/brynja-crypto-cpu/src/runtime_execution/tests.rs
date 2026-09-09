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
        stale.compress_sha256(&mut state, &[0; 64]),
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
        session.compress_sha256(&mut state32, &[0; 64]),
        Err(Error::Quarantined)
    );
    assert_eq!(
        session.compress_sha512(&mut state64, &[0; 128]),
        Err(Error::Quarantined)
    );
    assert_eq!(session.permute_keccak(&mut lanes), Err(Error::Quarantined));
    assert_eq!(state32, [13; 8]);
    assert_eq!(state64, [17; 8]);
    assert_eq!(lanes, [19; 25]);
}

#[test]
fn exact_architecture_inventory() {
    for kernel in Kernel::ALL {
        let x86 = matches!(kernel, Kernel::X86Sha256 | Kernel::X86Keccak);
        let expected =
            (x86 && cfg!(target_arch = "x86_64")) || (!x86 && cfg!(target_arch = "aarch64"));
        assert_eq!(operations::architecture(kernel).is_ok(), expected);
    }
}
