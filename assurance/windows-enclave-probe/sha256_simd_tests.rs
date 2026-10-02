use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};
fn authority() -> Authority {
    Authority::for_compiled_target(Kernel::Avx2).unwrap()
}
fn plan() -> [Algorithm; 8] {
    [
        Algorithm::Sha224,
        Algorithm::Sha256,
        Algorithm::Sha224,
        Algorithm::Sha256,
        Algorithm::Sha224,
        Algorithm::Sha256,
        Algorithm::Sha224,
        Algorithm::Sha256,
    ]
}
fn inputs<'a>(data: &'a [u8], plan: [Algorithm; 8], last: u8) -> [Lane<'a>; 8] {
    plan.map(|identity| Lane {
        identity,
        bytes: data,
        last,
    })
}
fn cleared(owner: &Owner<'_>) {
    assert!(owner.output.iter().all(|byte| *byte == 0));
    assert_eq!(owner.plan, None);
}
#[test]
fn real_vector_execution_and_reuse() {
    let a = authority();
    let mut owner = Owner::new(&a).unwrap();
    for sequence in (1..=9).step_by(2) {
        let report = owner
            .digest(sequence, inputs(&[7; 129], plan(), 8), 100)
            .unwrap();
        assert_eq!(report.kernel, Some(Kernel::Avx2));
        assert_eq!(report.vector_calls, 2);
        assert_eq!(report.vector_blocks, 16);
        assert_eq!(report.scalar_blocks, 8);
        owner
            .export_public(sequence + 1, plan(), |out| {
                assert!(out.iter().any(|byte| *byte != 0));
                for (slot, id) in out.chunks_exact(32).zip(plan()) {
                    assert!(slot[id.output_bytes()..].iter().all(|byte| *byte == 0));
                }
                true
            })
            .unwrap();
        cleared(&owner);
    }
}
#[test]
fn rejects_ineligible_oversized_and_noncanonical_input_without_fallback() {
    for (len, last, fill, expected) in [
        (0, 0, 0, Error::Work),
        (63, 8, 0, Error::Work),
        (64, 7, 0, Error::Work),
        (1025, 8, 0, Error::Length),
        (65, 1, 1, Error::Bits),
        (65, 9, 0, Error::Bits),
    ] {
        for index in 0..8 {
            let a = authority();
            let mut owner = Owner::new(&a).unwrap();
            let data = std::vec![fill; len];
            let mut lanes = inputs(&[0; 64], plan(), 8);
            lanes[index].bytes = &data;
            lanes[index].last = last;
            assert_eq!(owner.digest(1, lanes, 100), Err(expected));
            cleared(&owner);
            assert!(!a.is_healthy());
            assert!(owner.digest(2, inputs(&[0; 64], plan(), 8), 100).is_err());
        }
    }
}
#[test]
fn retained_results_cannot_be_replaced_or_exported_twice() {
    let a = authority();
    let mut owner = Owner::new(&a).unwrap();
    owner.digest(1, inputs(&[3; 64], plan(), 8), 100).unwrap();
    assert_eq!(
        owner.digest(2, inputs(&[4; 64], plan(), 8), 100),
        Err(Error::State)
    );
    cleared(&owner);
    assert!(!a.is_healthy());

    for exported in [false, true] {
        let a = authority();
        let mut owner = Owner::new(&a).unwrap();
        let sequence = if exported {
            owner.digest(1, inputs(&[3; 64], plan(), 8), 100).unwrap();
            owner.export_public(2, plan(), |_| true).unwrap();
            3
        } else {
            1
        };
        let mut called = false;
        assert_eq!(
            owner.export_public(sequence, plan(), |_| {
                called = true;
                true
            }),
            Err(Error::State)
        );
        assert!(!called);
        cleared(&owner);
        assert!(!a.is_healthy());
    }
}
#[test]
fn missing_common_group_and_revoked_constructor_fail_closed() {
    for index in 0..8 {
        let a = authority();
        let mut owner = Owner::new(&a).unwrap();
        let mut lanes = inputs(&[0; 256], plan(), 8);
        lanes[index].bytes = &[0; 63];
        assert_eq!(owner.digest(1, lanes, 100), Err(Error::Work));
        cleared(&owner);
        assert!(!a.is_healthy());
        assert!(matches!(Owner::new(&a), Err(Error::Backend)));
        assert_eq!(owner.cancel(2), Err(Error::State));
    }
}
#[test]
fn budget_and_sequence_failure_clear_and_quarantine() {
    for budget in 0..24 {
        let a = authority();
        let mut owner = Owner::new(&a).unwrap();
        assert_eq!(
            owner.digest(1, inputs(&[4; 129], plan(), 8), budget),
            Err(Error::Work)
        );
        cleared(&owner);
        assert!(!a.is_healthy());
    }
    let a = authority();
    let mut exact = Owner::new(&a).unwrap();
    let report = exact.digest(1, inputs(&[4; 129], plan(), 8), 24).unwrap();
    assert_eq!(report.vector_blocks + report.scalar_blocks, 24);
    exact.cancel(2).unwrap();
    let a = authority();
    let mut owner = Owner::new(&a).unwrap();
    owner.digest(1, inputs(&[4; 64], plan(), 8), 100).unwrap();
    assert_eq!(owner.cancel(3), Err(Error::Sequence));
    cleared(&owner);
    assert!(!a.is_healthy());
    let a = authority();
    let mut owner = Owner::new(&a).unwrap();
    owner.sequence = u64::MAX;
    assert_eq!(owner.cancel(0), Err(Error::Sequence));
    cleared(&owner);
    assert!(!a.is_healthy());
}
#[test]
fn retained_failures_revocation_and_unwind_clear() {
    for mode in 0..4 {
        let a = authority();
        let mut owner = Owner::new(&a).unwrap();
        owner.digest(1, inputs(&[9; 129], plan(), 8), 100).unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| {
            if mode == 0 {
                a.quarantine();
            }
            owner.export_public(
                2,
                if mode == 1 {
                    [Algorithm::Sha256; 8]
                } else {
                    plan()
                },
                |_| {
                    if mode == 2 {
                        a.quarantine();
                    }
                    if mode == 3 {
                        panic!("test unwind");
                    }
                    mode != 0
                },
            )
        }));
        assert!(matches!(result, Err(_) | Ok(Err(_))));
        cleared(&owner);
        assert!(!a.is_healthy());
    }
    let a = authority();
    let mut owner = Owner::new(&a).unwrap();
    owner.digest(1, inputs(&[9; 129], plan(), 8), 100).unwrap();
    assert_eq!(owner.export_public(2, plan(), |_| false), Err(Error::Copy));
    cleared(&owner);
}
#[test]
fn cancel_and_drop_destroy_retained_state() {
    let a = authority();
    let mut owner = Owner::new(&a).unwrap();
    owner.digest(1, inputs(&[1; 64], plan(), 8), 100).unwrap();
    owner.cancel(2).unwrap();
    cleared(&owner);
    assert!(a.is_healthy());
    owner.digest(3, inputs(&[2; 64], plan(), 8), 100).unwrap();
    drop(owner);
    assert!(!a.is_healthy());
}
