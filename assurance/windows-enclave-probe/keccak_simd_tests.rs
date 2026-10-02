use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};
fn authority() -> Authority {
    Authority::for_compiled_target(Kernel::Avx2).unwrap()
}
fn bits(data: &[u8], last: u8) -> Fips202BitString<'_> {
    Fips202BitString::new(data, last).unwrap()
}
fn plan() -> [Slot; 4] {
    [Slot {
        identity: Algorithm::Sha3_256,
        output_bits: 256,
    }; 4]
}
fn inputs(data: &[u8]) -> [Lane<'_>; 4] {
    plan().map(|slot| Lane {
        slot,
        message: bits(data, if data.is_empty() { 0 } else { 8 }),
        name: bits(&[], 0),
        custom: bits(&[], 0),
    })
}
fn cleared(owner: &Owner<'_>) {
    assert!(owner.output.iter().all(|byte| *byte == 0));
    assert_eq!(owner.plan, None);
}
#[test]
fn vector_execution_zero_padding_and_reuse() {
    let a = authority();
    let mut owner = Owner::new(&a).unwrap();
    for sequence in (1..=9).step_by(2) {
        let report = owner.digest(sequence, inputs(&[7; 200]), 8).unwrap();
        assert_eq!(report.kernel, Some(Kernel::Avx2));
        assert_eq!(report.vector_calls, 2);
        assert_eq!(report.vector_permutations, 8);
        assert_eq!(report.scalar_permutations, 0);
        assert_eq!(report.accelerated_slots, 15);
        owner
            .export_public(sequence + 1, plan(), |out| {
                assert!(out.iter().any(|byte| *byte != 0));
                for slot in out.chunks_exact(256) {
                    assert!(slot[32..].iter().all(|byte| *byte == 0));
                }
                true
            })
            .unwrap();
        cleared(&owner);
    }
}
#[test]
fn bounds_and_identity_rejection_quarantine() {
    for lane in 0..4 {
        for mode in 0..6 {
            let a = authority();
            let mut owner = Owner::new(&a).unwrap();
            let mut request = inputs(&[0; 200]);
            let oversized = [0; 1025];
            match mode {
                0 => request[lane].message = bits(&oversized, 1),
                1 => request[lane].name = bits(&oversized, 1),
                2 => request[lane].custom = bits(&oversized, 1),
                3 => request[lane].slot.output_bits = 2049,
                4 => request[lane].slot.output_bits = 255,
                _ => request[lane].name = bits(&[1], 1),
            }
            assert_eq!(
                owner.digest(1, request, 100),
                Err(if mode < 4 {
                    Error::Length
                } else {
                    Error::Identity
                })
            );
            cleared(&owner);
            assert!(!a.is_healthy());
            assert!(owner.digest(2, inputs(&[0; 200]), 100).is_err());
            assert!(matches!(Owner::new(&a), Err(Error::Backend)));
        }
    }
}
#[test]
fn budget_sequence_and_overflow_fail_closed() {
    for budget in 0..8 {
        let a = authority();
        let mut owner = Owner::new(&a).unwrap();
        assert_eq!(owner.digest(1, inputs(&[7; 200]), budget), Err(Error::Work));
        cleared(&owner);
        assert!(!a.is_healthy());
    }
    for sequence in [0, 2, u64::MAX] {
        let a = authority();
        let mut owner = Owner::new(&a).unwrap();
        assert_eq!(
            owner.digest(sequence, inputs(&[0; 200]), 100),
            Err(Error::Sequence)
        );
        cleared(&owner);
        assert!(!a.is_healthy());
    }
    let a = authority();
    let mut owner = Owner::new(&a).unwrap();
    owner.sequence = u64::MAX;
    assert_eq!(owner.cancel(0), Err(Error::Sequence));
    assert!(!a.is_healthy());
}
#[test]
fn retained_identity_includes_output_bits_and_slot_order() {
    for mode in 0..3 {
        let a = authority();
        let mut owner = Owner::new(&a).unwrap();
        let mut request = inputs(&[0; 200]);
        request[0].slot = Slot {
            identity: Algorithm::Shake256,
            output_bits: 255,
        };
        let original = request.each_ref().map(|r| r.slot);
        owner.digest(1, request, 100).unwrap();
        let mut wrong = original;
        match mode {
            0 => wrong[0].output_bits = 256,
            1 => wrong[0].identity = Algorithm::Cshake256,
            _ => wrong.swap(0, 1),
        }
        assert_eq!(
            owner.export_public(2, wrong, |_| panic!("must not copy")),
            Err(Error::Identity)
        );
        cleared(&owner);
        assert!(!a.is_healthy());
    }
}
#[test]
fn retained_state_cannot_be_replaced_or_exported_twice() {
    let a = authority();
    let mut owner = Owner::new(&a).unwrap();
    owner.digest(1, inputs(&[1; 200]), 100).unwrap();
    assert_eq!(owner.digest(2, inputs(&[2; 200]), 100), Err(Error::State));
    cleared(&owner);
    assert!(!a.is_healthy());
    for exported in [false, true] {
        let a = authority();
        let mut owner = Owner::new(&a).unwrap();
        let sequence = if exported {
            owner.digest(1, inputs(&[1; 200]), 100).unwrap();
            owner.export_public(2, plan(), |_| true).unwrap();
            3
        } else {
            1
        };
        assert_eq!(
            owner.export_public(sequence, plan(), |_| panic!("must not copy")),
            Err(Error::State)
        );
        cleared(&owner);
        assert!(!a.is_healthy());
    }
}
#[test]
fn revocation_copy_failure_and_unwind_clear() {
    for mode in 0..4 {
        let a = authority();
        let mut owner = Owner::new(&a).unwrap();
        owner.digest(1, inputs(&[9; 200]), 100).unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| {
            if mode == 0 {
                a.quarantine();
            }
            owner.export_public(2, plan(), |_| {
                if mode == 1 {
                    a.quarantine();
                }
                if mode == 2 {
                    panic!("test unwind");
                }
                mode != 3
            })
        }));
        assert!(matches!(result, Err(_) | Ok(Err(_))));
        cleared(&owner);
        assert!(!a.is_healthy());
    }
}
#[test]
fn cancel_drop_and_zero_output_are_not_fallbacks() {
    let a = authority();
    let mut owner = Owner::new(&a).unwrap();
    owner.digest(1, inputs(&[1; 200]), 100).unwrap();
    owner.cancel(2).unwrap();
    cleared(&owner);
    assert!(a.is_healthy());
    let mut request = inputs(&[]);
    for lane in &mut request {
        lane.slot = Slot {
            identity: Algorithm::Shake128,
            output_bits: 0,
        };
    }
    let plan = request.each_ref().map(|r| r.slot);
    let report = owner.digest(3, request, 4).unwrap();
    assert_eq!(report.vector_calls, 1);
    assert_eq!(report.accelerated_slots, 15);
    owner
        .export_public(4, plan, |out| {
            assert_eq!(out, &[0; 1024]);
            true
        })
        .unwrap();
    owner.digest(5, inputs(&[2; 200]), 100).unwrap();
    drop(owner);
    assert!(!a.is_healthy());
}
