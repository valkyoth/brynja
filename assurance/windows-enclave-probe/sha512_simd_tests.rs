use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};
fn authority() -> Authority {
    Authority::for_compiled_target(Kernel::Avx2).unwrap()
}
fn plan() -> [Algorithm; 4] {
    [
        Algorithm::Sha384,
        Algorithm::Sha512,
        Algorithm::Sha512_224,
        Algorithm::Sha512_256,
    ]
}
fn inputs<'a>(data: &'a [u8], plan: [Algorithm; 4], last: u8) -> [Lane<'a>; 4] {
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
            .digest(sequence, inputs(&[7; 257], plan(), 8), 100)
            .unwrap();
        assert_eq!(report.kernel, Some(Kernel::Avx2));
        assert_eq!(report.vector_calls, 2);
        assert_eq!(report.vector_blocks, 8);
        assert_eq!(report.scalar_blocks, 4);
        owner
            .export_public(sequence + 1, plan(), |out| {
                assert!(out.iter().any(|byte| *byte != 0));
                for (slot, id) in out.chunks_exact(64).zip(plan()) {
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
        (127, 8, 0, Error::Work),
        (128, 7, 0, Error::Work),
        (1025, 8, 0, Error::Length),
        (129, 1, 1, Error::Bits),
        (129, 9, 0, Error::Bits),
    ] {
        let a = authority();
        let mut owner = Owner::new(&a).unwrap();
        assert_eq!(
            owner.digest(1, inputs(&std::vec![fill;len], plan(), last), 100),
            Err(expected)
        );
        cleared(&owner);
        assert!(!a.is_healthy());
        assert!(owner.digest(2, inputs(&[0; 128], plan(), 8), 100).is_err());
    }
}
#[test]
fn retained_results_cannot_be_replaced_or_exported_twice() {
    let a = authority();
    let mut owner = Owner::new(&a).unwrap();
    owner.digest(1, inputs(&[3; 128], plan(), 8), 100).unwrap();
    assert_eq!(
        owner.digest(2, inputs(&[4; 128], plan(), 8), 100),
        Err(Error::State)
    );
    cleared(&owner);
    assert!(!a.is_healthy());

    for exported in [false, true] {
        let a = authority();
        let mut owner = Owner::new(&a).unwrap();
        let sequence = if exported {
            owner.digest(1, inputs(&[3; 128], plan(), 8), 100).unwrap();
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
    let a = authority();
    let mut owner = Owner::new(&a).unwrap();
    let mut lanes = inputs(&[0; 256], plan(), 8);
    lanes[3].bytes = &[0; 127];
    assert_eq!(owner.digest(1, lanes, 100), Err(Error::Work));
    cleared(&owner);
    assert!(!a.is_healthy());
    assert!(matches!(Owner::new(&a), Err(Error::Backend)));
    assert_eq!(owner.cancel(2), Err(Error::State));
}
#[test]
fn budget_and_sequence_failure_clear_and_quarantine() {
    for budget in 0..12 {
        let a = authority();
        let mut owner = Owner::new(&a).unwrap();
        assert_eq!(
            owner.digest(1, inputs(&[4; 257], plan(), 8), budget),
            Err(Error::Work)
        );
        cleared(&owner);
        assert!(!a.is_healthy());
    }
    let a = authority();
    let mut owner = Owner::new(&a).unwrap();
    owner.digest(1, inputs(&[4; 128], plan(), 8), 100).unwrap();
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
                    [Algorithm::Sha512; 4]
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
    owner.digest(1, inputs(&[1; 128], plan(), 8), 100).unwrap();
    owner.cancel(2).unwrap();
    cleared(&owner);
    assert!(a.is_healthy());
    owner.digest(3, inputs(&[2; 128], plan(), 8), 100).unwrap();
    drop(owner);
    assert!(!a.is_healthy());
}
