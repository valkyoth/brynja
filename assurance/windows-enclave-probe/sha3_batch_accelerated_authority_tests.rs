use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn authority() -> Authority {
    Authority::new(Kernel::X86Keccak).unwrap()
}
fn plan() -> [Slot; 8] {
    let mut plan = [Slot::default(); 8];
    plan[0] = Slot {
        identity: 7,
        width: 33,
        last: 3,
    };
    plan
}
fn at(authority: &Authority, stage: usize) -> Owner<'_> {
    let mut owner = Owner::new(authority).unwrap();
    if stage >= 1 {
        owner.begin(1, plan(), 100).unwrap();
    }
    if stage >= 2 {
        owner.start(2, 0, 0, 0).unwrap();
    }
    if stage >= 3 {
        owner.finish_setup(3, 0).unwrap();
    }
    if stage >= 4 {
        owner.finish(4, 0, b"abc", 8).unwrap();
    }
    if stage >= 5 {
        owner.seal(5).unwrap();
    }
    owner
}
fn failed(owner: &Owner<'_>) {
    assert_eq!(owner.phase, Phase::Quarantined);
    assert!(matches!(owner.state, State::Empty));
    assert_eq!(owner.output, [0; 1024]);
    assert_eq!(owner.plan, [Slot::default(); 8]);
    assert_eq!(owner.active, None);
    assert_eq!(owner.completed, 0);
    assert_eq!(owner.remaining, 0);
    assert!(owner.authority.session().is_err());
}
#[test]
fn revoked_authority_rejects_every_operation_including_zero_work() {
    if let Ok(wrong) = Authority::new(Kernel::X86Sha256) {
        assert!(matches!(Owner::new(&wrong), Err(Error::Crypto)));
    }
    for (mode, stage) in [0, 1, 2, 2, 3, 3, 4, 5, 1].into_iter().enumerate() {
        let authority = authority();
        let mut owner = at(&authority, stage);
        authority.quarantine();
        let n = owner.sequence + 1;
        let result = match mode {
            0 => owner.begin(n, plan(), 0),
            1 => owner.start(n, 0, 0, 0),
            2 => owner.setup_chunk(n, 0, true, &[], 0),
            3 => owner.finish_setup(n, 0),
            4 => owner.update(n, 0, &[]),
            5 => owner.finish(n, 0, &[], 0),
            6 => owner.seal(n),
            7 => owner.export(n, plan(), |_| panic!("revoked export")),
            _ => owner.cancel(n),
        };
        assert_eq!(result, Err(Error::Crypto), "mode {mode}");
        failed(&owner);
        assert!(matches!(Owner::new(&authority), Err(Error::Crypto)));
    }
}
#[test]
fn copy_failure_revocation_and_unwind_clear_and_revoke() {
    for mode in 0..3 {
        let authority = authority();
        let mut owner = at(&authority, 5);
        assert!(owner.output.iter().any(|b| *b != 0));
        match mode {
            0 => assert_eq!(owner.export(6, plan(), |_| false), Err(Error::Copy)),
            1 => assert!(
                catch_unwind(AssertUnwindSafe(
                    || owner.export(6, plan(), |_| panic!("copy fault"))
                ))
                .is_err()
            ),
            _ => assert_eq!(
                owner.export(6, plan(), |_| {
                    authority.quarantine();
                    true
                }),
                Err(Error::Crypto)
            ),
        }
        failed(&owner);
    }
}
#[test]
fn cancel_and_export_preserve_reuse_but_drop_revokes() {
    for stage in 1..=5 {
        let authority = authority();
        {
            let mut owner = at(&authority, stage);
            let mut n = owner.sequence + 1;
            owner.cancel(n).unwrap();
            assert_eq!(owner.output, [0; 1024]);
            assert!(matches!(owner.state, State::Empty));
            assert!(authority.session().is_ok());
            n += 1;
            owner.begin(n, plan(), 0).unwrap();
            owner.start(n + 1, 0, 0, 0).unwrap();
            owner.finish_setup(n + 2, 0).unwrap();
            owner.finish(n + 3, 0, &[], 0).unwrap();
            owner.seal(n + 4).unwrap();
            owner
                .export(n + 5, plan(), |out| {
                    assert!(out[33..].iter().all(|b| *b == 0));
                    true
                })
                .unwrap();
            assert_eq!(owner.output, [0; 1024]);
            assert_eq!(owner.phase, Phase::Empty);
            assert!(authority.session().is_ok());
        }
        assert!(authority.session().is_err());
    }
}
