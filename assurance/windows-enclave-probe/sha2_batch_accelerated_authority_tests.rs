use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn authority() -> Authority {
    Authority::new(Kernel::X86Sha256).unwrap()
}
fn plan() -> [u64; 8] {
    [2, 0, 0, 0, 0, 0, 0, 0]
}
fn at(a: &Authority, stage: usize) -> Owner<'_> {
    let mut o = Owner::new(a).unwrap();
    if stage >= 1 {
        o.begin(1, plan(), 3).unwrap();
    }
    if stage >= 2 {
        o.start(2, 0).unwrap();
    }
    if stage >= 3 {
        o.finish(3, 0, b"abc", 8).unwrap();
    }
    if stage >= 4 {
        o.seal(4).unwrap();
    }
    o
}
fn failed(o: &Owner<'_>) {
    assert_eq!(o.phase, Phase::Quarantined);
    assert!(o.state.is_none());
    assert_eq!(o.output, [0; 512]);
    assert_eq!(o.plan, [0; 8]);
    assert_eq!(o.active, None);
    assert_eq!(o.completed, 0);
    assert_eq!(o.remaining, 0);
    assert!(o.authority.session().is_err());
}
#[test]
fn revocation_rejects_every_boundary_even_without_compression() {
    let wrong = Authority::new(Kernel::X86Keccak).unwrap();
    assert!(matches!(Owner::new(&wrong), Err(Error::Backend)));
    for (mode, stage) in [0, 1, 2, 2, 3, 4, 1].into_iter().enumerate() {
        let a = authority();
        let mut o = at(&a, stage);
        a.quarantine();
        let n = o.sequence + 1;
        let result = match mode {
            0 => o.begin(n, plan(), 0),
            1 => o.start(n, 0),
            2 => o.update(n, 0, &[]),
            3 => o.finish(n, 0, &[], 0),
            4 => o.seal(n),
            5 => o.export(n, plan(), |_| panic!("revoked export")),
            _ => o.cancel(n),
        };
        assert_eq!(result, Err(Error::Backend), "{mode}");
        failed(&o);
        assert!(matches!(Owner::new(&a), Err(Error::Backend)));
    }
}
#[test]
fn copy_failure_revocation_unwind_and_drop_revoke_authority() {
    for mode in 0..3 {
        let a = authority();
        let mut o = at(&a, 4);
        match mode {
            0 => assert_eq!(o.export(5, plan(), |_| false), Err(Error::Copy)),
            1 => assert!(
                catch_unwind(AssertUnwindSafe(
                    || o.export(5, plan(), |_| panic!("copy fault"))
                ))
                .is_err()
            ),
            _ => assert_eq!(
                o.export(5, plan(), |_| {
                    a.quarantine();
                    true
                }),
                Err(Error::Backend)
            ),
        }
        failed(&o);
    }
    for stage in 0..=4 {
        let a = authority();
        drop(at(&a, stage));
        assert!(a.session().is_err());
    }
}
#[test]
fn cancel_and_export_reuse_preserve_authority_and_static_route() {
    for stage in 1..=4 {
        let a = authority();
        let mut o = at(&a, stage);
        let mut n = o.sequence + 1;
        o.cancel(n).unwrap();
        assert!(a.session().is_ok());
        n += 1;
        o.begin(n, plan(), 0).unwrap();
        n += 1;
        o.start(n, 0).unwrap();
        let route = match o.state.as_ref().unwrap() {
            State::A(s) => s.report().route,
            State::B(s) => s.report().route,
        };
        assert_eq!(
            route,
            brynja_hash_sha2::execution::Route::Static(Kernel::X86Sha256)
        );
        n += 1;
        o.finish(n, 0, &[], 0).unwrap();
        n += 1;
        o.seal(n).unwrap();
        n += 1;
        o.export(n, plan(), |v| {
            assert!(v[32..].iter().all(|b| *b == 0));
            true
        })
        .unwrap();
        assert_eq!(o.phase, Phase::Empty);
        assert_eq!(o.output, [0; 512]);
        assert!(a.session().is_ok());
    }
}
#[test]
fn wide_or_invalid_plan_and_wrong_phase_never_select_portable() {
    for id in [3, 4, 5, 6, 7, 0x1001, 0x1180, 0x11ff, u64::MAX] {
        let a = authority();
        let mut o = Owner::new(&a).unwrap();
        let mut p = plan();
        p[7] = id;
        assert_eq!(o.begin(1, p, 0), Err(Error::Identity));
        failed(&o);
    }
    for stage in [0, 1, 2, 3, 4] {
        let a = authority();
        let mut o = at(&a, stage);
        let n = o.sequence + 1;
        let result = if stage == 0 {
            o.cancel(n)
        } else {
            o.begin(n, plan(), 0)
        };
        assert_eq!(result, Err(Error::State));
        failed(&o);
    }
}
