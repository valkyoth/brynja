extern crate std;
use super::*;
use persistent_result::PUBLIC_OUTPUT;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn oracle(input: &[u8], expected: &[u8]) {
    let mut retained = [0xa5; 32];
    let mut owner = Owner::new(&mut retained, [7, 9]).unwrap();
    let token = {
        let mut workspace = Sha256Workspace::new();
        let mut staging = [0xa5; 32];
        let token = owner.hash(&mut workspace, &mut staging, input).unwrap();
        assert_eq!(staging, [0; 32]);
        token
    }; // Scratch and workspace cease to exist before later export.
    let mut public = [0xa5; 32];
    owner
        .export_public(token, PUBLIC_OUTPUT, |bytes| {
            public.copy_from_slice(bytes);
            true
        })
        .unwrap();
    assert_eq!(public.as_slice(), expected);
    assert_eq!(owner.cancel(token), Err(Error::Spent));
    drop(owner);
    assert_eq!(retained, [0; 32]);
}

#[test]
fn cancel_reuse_abandonment_and_busy_preserve_ownership() {
    let mut retained = [0xa5; 32];
    {
        let mut owner = Owner::new(&mut retained, [7, 9]).unwrap();
        let mut workspace = Sha256Workspace::new();
        let mut staging = [0xa5; 32];
        let first = owner.hash(&mut workspace, &mut staging, b"abc").unwrap();
        staging.fill(0xa5);
        assert_eq!(
            owner.hash(&mut workspace, &mut staging, b"other"),
            Err(Error::Busy)
        );
        assert_eq!(staging, [0; 32]);
        owner.cancel(first).unwrap();
        let next = owner.hash(&mut workspace, &mut staging, b"def").unwrap();
        assert_eq!(next[2], first[2] + 1);
        assert_eq!(
            owner.export_public(first, PUBLIC_OUTPUT, |_| panic!("stale")),
            Err(Error::Rejected)
        );
        assert_eq!(owner.cancel(next), Err(Error::Spent));
        owner
            .hash(&mut workspace, &mut staging, b"abandoned")
            .unwrap();
    }
    assert_eq!(retained, [0; 32]);
}

#[test]
fn failed_and_unwinding_export_are_terminal() {
    for unwind in [false, true] {
        let mut retained = [0xa5; 32];
        {
            let mut owner = Owner::new(&mut retained, [7, 9]).unwrap();
            let mut workspace = Sha256Workspace::new();
            let mut staging = [0xa5; 32];
            let token = owner.hash(&mut workspace, &mut staging, b"abc").unwrap();
            let run = catch_unwind(AssertUnwindSafe(|| {
                assert_eq!(
                    owner.export_public(token, PUBLIC_OUTPUT, |_| {
                        if unwind {
                            panic!("copy fault");
                        }
                        false
                    }),
                    Err(Error::Copy)
                );
            }));
            assert_eq!(run.is_err(), unwind);
            assert_eq!(
                owner.hash(&mut workspace, &mut staging, b"reuse"),
                Err(Error::Quarantined)
            );
        }
        assert_eq!(retained, [0; 32]);
    }
}

#[test]
fn export_requires_public_acknowledgment_and_quarantine_is_terminal() {
    let mut retained = [0xa5; 32];
    {
        let mut owner = Owner::new(&mut retained, [7, 9]).unwrap();
        let mut workspace = Sha256Workspace::new();
        let mut staging = [0xa5; 32];
        let token = owner.hash(&mut workspace, &mut staging, b"abc").unwrap();
        assert_eq!(
            owner.export_public(token, 0, |_| panic!("implicit public output")),
            Err(Error::Rejected)
        );
        assert_eq!(owner.cancel(token), Err(Error::Spent));
        owner.hash(&mut workspace, &mut staging, b"abc").unwrap();
        owner.quarantine();
        assert_eq!(
            owner.hash(&mut workspace, &mut staging, b"abc"),
            Err(Error::Quarantined)
        );
        owner.close();
        assert_eq!(owner.cancel(token), Err(Error::Closed));
    }
    assert_eq!(retained, [0; 32]);
}
