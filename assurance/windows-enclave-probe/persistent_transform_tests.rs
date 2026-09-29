extern crate std;
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn filled(slot: &mut Slot<'_>) -> [u64; 4] {
    slot.fill(|bytes| {
        bytes.fill(0x5a);
        true
    })
    .unwrap()
}

#[test]
fn transform_replaces_value_and_generation_without_export() {
    let mut bytes = [0xa5; 32];
    let mut slot = Slot::new(&mut bytes, [7, 9]).unwrap();
    let old = filled(&mut slot);
    let mut candidate = [0xa5; 32];
    let next = slot
        .transform_secret(old, &mut candidate, |input, output| {
            assert_eq!(input, &[0x5a; 32]);
            assert_eq!(output, &[0; 32]);
            output.fill(0x36);
            true
        })
        .unwrap();
    assert_eq!(candidate, [0; 32]);
    assert_eq!(next, [7, 9, old[2] + 1, 1]);
    assert_eq!(slot.bytes, &[0x36; 32]);
    assert!(slot.state == State::Ready);
    slot.cancel(next).unwrap();
    assert_eq!(slot.bytes, &[0; 32]);
}

#[test]
fn every_partial_failure_or_unwind_clears_old_and_new_result() {
    for width in 0..=32 {
        for unwind in [false, true] {
            let mut bytes = [0xa5; 32];
            let mut slot = Slot::new(&mut bytes, [7, 9]).unwrap();
            let token = filled(&mut slot);
            let mut candidate = [0xa5; 32];
            let result = catch_unwind(AssertUnwindSafe(|| {
                assert_eq!(
                    slot.transform_secret(token, &mut candidate, |input, output| {
                        assert_eq!(input, &[0x5a; 32]);
                        output[..width].fill(0x81);
                        assert!(!unwind, "controlled transform unwind");
                        false
                    }),
                    Err(Error::Fill)
                );
            }));
            assert_eq!(result.is_err(), unwind);
            assert_eq!(candidate, [0; 32]);
            assert_eq!(slot.bytes, &[0; 32]);
            assert!(slot.state == State::Quarantined);
            assert_eq!(
                slot.fill(|_| panic!("quarantined")),
                Err(Error::Quarantined)
            );
        }
    }
}

#[test]
fn wrong_cross_owner_and_stale_tokens_never_enter_operation() {
    for field in 0..4 {
        let mut bytes = [0xa5; 32];
        let mut slot = Slot::new(&mut bytes, [7, 9]).unwrap();
        let mut token = filled(&mut slot);
        token[field] ^= 1;
        let mut candidate = [0xa5; 32];
        assert_eq!(
            slot.transform_secret(token, &mut candidate, |_, _| panic!("wrong token")),
            Err(Error::Rejected)
        );
        assert_eq!(candidate, [0; 32]);
        assert_eq!(slot.bytes, &[0; 32]);
        assert!(slot.state == State::Quarantined);
    }
    let mut bytes = [0xa5; 32];
    let mut slot = Slot::new(&mut bytes, [7, 9]).unwrap();
    let old = filled(&mut slot);
    let mut candidate = [0; 32];
    slot.transform_secret(old, &mut candidate, |_, out| {
        out.fill(1);
        true
    })
    .unwrap();
    assert_eq!(
        slot.transform_secret(old, &mut candidate, |_, _| panic!("stale")),
        Err(Error::Rejected)
    );
    assert_eq!(slot.bytes, &[0; 32]);
}

#[test]
fn exhausted_generation_is_terminal_and_nonready_attempts_clear_candidate() {
    let mut bytes = [0xa5; 32];
    let mut slot = Slot::new(&mut bytes, [7, 9]).unwrap();
    let mut candidate = [0xa5; 32];
    assert_eq!(
        slot.transform_secret([0; 4], &mut candidate, |_, _| panic!("idle")),
        Err(Error::Spent)
    );
    assert_eq!(candidate, [0; 32]);
    filled(&mut slot);
    slot.generation = u64::MAX;
    let token = slot.token();
    candidate.fill(0xa5);
    assert_eq!(
        slot.transform_secret(token, &mut candidate, |_, _| panic!("overflow")),
        Err(Error::Exhausted)
    );
    assert_eq!(candidate, [0; 32]);
    assert_eq!(slot.bytes, &[0; 32]);
    assert!(slot.state == State::Quarantined);
    slot.close();
    candidate.fill(0xa5);
    assert_eq!(
        slot.transform_secret(token, &mut candidate, |_, _| panic!("closed")),
        Err(Error::Closed)
    );
    assert_eq!(candidate, [0; 32]);
}
