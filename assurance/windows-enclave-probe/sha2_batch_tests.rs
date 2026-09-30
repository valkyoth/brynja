use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn clean(owner: &Owner) {
    assert_eq!(owner.output, [0; 512]);
    assert!(owner.state.is_none());
    assert!(owner.active.is_none());
    assert_eq!(owner.completed, 0);
    assert_eq!(owner.plan, [0; 8]);
}
fn failed(owner: &Owner) {
    clean(owner);
    assert_eq!(owner.phase, Phase::Quarantined);
}
fn retained() -> Owner {
    let mut o = Owner::new();
    o.begin(1, [2, 0, 0, 0, 0, 0, 0, 0], 3).unwrap();
    o.start(2, 0).unwrap();
    o.finish(3, 0, b"abc", 8).unwrap();
    o.seal(4).unwrap();
    o
}
fn check_case(identity: u64, message: &[u8], last: u8, expected: &[u8]) {
    let mut o = Owner::new();
    let plan = [identity; 8];
    o.begin(1, plan, (message.len() * 8) as u64).unwrap();
    let mut n = 1;
    for slot in 0..8 {
        n += 1;
        o.start(n, slot).unwrap();
        let split = message.len().saturating_sub(1);
        for chunk in message[..split].chunks(113) {
            n += 1;
            o.update(n, slot, &[]).unwrap();
            n += 1;
            o.update(n, slot, chunk).unwrap();
        }
        n += 1;
        o.finish(n, slot, &message[split..], last).unwrap();
    }
    n += 1;
    o.seal(n).unwrap();
    n += 1;
    o.export(n, plan, |bytes| {
        for slot in bytes.chunks_exact(64) {
            assert_eq!(&slot[..expected.len()], expected);
            assert!(slot[expected.len()..].iter().all(|v| *v == 0));
        }
        true
    })
    .unwrap();
    clean(&o);
    assert_eq!(o.phase, Phase::Empty);
    n += 1;
    o.begin(n, plan, 0).unwrap();
    n += 1;
    o.cancel(n).unwrap();
    clean(&o);
}
#[test]
fn every_activity_mask_preserves_slot_identity_and_zero_padding() {
    use brynja_hash_sha2::sha256;
    for mask in 1_u16..=255 {
        let plan = core::array::from_fn(|i| if mask & (1 << i) != 0 { 2 } else { 0 });
        let mut o = Owner::new();
        o.begin(1, plan, 24).unwrap();
        let mut n = 1;
        for slot in 0..8 {
            if plan[slot] == 0 {
                continue;
            }
            n += 1;
            o.start(n, slot).unwrap();
            n += 1;
            o.finish(n, slot, &[slot as u8; 3], 8).unwrap();
        }
        n += 1;
        o.seal(n).unwrap();
        n += 1;
        o.export(n, plan, |bytes| {
            for (slot, output) in bytes.chunks_exact(64).enumerate() {
                if plan[slot] == 0 {
                    assert_eq!(output, [0; 64]);
                } else {
                    assert_eq!(&output[..32], sha256(&[slot as u8; 3]).unwrap().as_bytes());
                    assert_eq!(&output[32..], [0; 32]);
                }
            }
            true
        })
        .unwrap();
        clean(&o);
    }
}
#[test]
fn general_t_and_partial_message_bits_match_scalar_reference() {
    use brynja_hash_sha2::*;
    for t in 1..512 {
        let Ok(t) = Sha512TBits::new(t) else { continue };
        for last in 1..=8 {
            let message = [0xab, 0xff << (8 - last)];
            let expected = sha512_t_bits(t, BitString::new(&message, last).unwrap()).unwrap();
            check_case(
                Algorithm::Sha512T(t).encode(),
                &message,
                last,
                expected.as_bytes(),
            );
        }
    }
}
#[test]
fn incomplete_out_of_order_duplicate_and_wrong_identity_fail_closed() {
    let mut o = Owner::new();
    o.begin(1, [2; 8], 24).unwrap();
    o.start(2, 0).unwrap();
    o.finish(3, 0, b"abc", 8).unwrap();
    assert!(
        o.export(4, [2; 8], |_| panic!("partial batch must not export"))
            .is_err()
    );
    failed(&o);
    for slot in [1, 7, 8, usize::MAX] {
        let mut o = Owner::new();
        o.begin(1, [2; 8], 24).unwrap();
        assert!(o.start(2, slot).is_err());
        failed(&o);
    }
    let mut o = Owner::new();
    o.begin(1, [2; 8], 24).unwrap();
    o.start(2, 0).unwrap();
    o.finish(3, 0, b"abc", 8).unwrap();
    assert!(o.start(4, 0).is_err());
    failed(&o);
    let mut o = Owner::new();
    o.begin(1, [2; 8], 24).unwrap();
    o.start(2, 0).unwrap();
    o.finish(3, 0, b"abc", 8).unwrap();
    assert!(o.seal(4).is_err());
    failed(&o);
    let mut o = Owner::new();
    o.begin(1, [2; 8], 24).unwrap();
    o.start(2, 0).unwrap();
    assert!(o.seal(3).is_err());
    failed(&o);
    let mut o = retained();
    assert!(o.export(5, [1; 8], |_| panic!("must not export")).is_err());
    failed(&o);
}
#[test]
fn bounded_input_budget_and_sequences_reject_without_retained_output() {
    let mut o = Owner::new();
    o.begin(1, [2; 8], 24).unwrap();
    o.start(2, 0).unwrap();
    assert!(o.finish(3, 0, &[1], 3).is_err());
    failed(&o);
    for budget in 0..3 {
        let mut o = Owner::new();
        o.begin(1, [2; 8], budget).unwrap();
        o.start(2, 0).unwrap();
        assert!(o.finish(3, 0, b"abc", 8).is_err());
        failed(&o);
    }
    for wrong_slot in [1, 8, usize::MAX] {
        let mut o = Owner::new();
        o.begin(1, [2; 8], 9999).unwrap();
        o.start(2, 0).unwrap();
        assert!(o.update(3, wrong_slot, b"abc").is_err());
        failed(&o);
    }
    let mut o = Owner::new();
    o.begin(1, [2; 8], 9999).unwrap();
    o.start(2, 0).unwrap();
    assert!(o.update(3, 0, &[0; 1025]).is_err());
    failed(&o);
    let mut o = Owner::new();
    o.begin(1, [2; 8], 9999).unwrap();
    o.start(2, 0).unwrap();
    assert!(o.finish(3, 0, &[0; 1025], 8).is_err());
    failed(&o);
    for sequence in [0, 1, 4, 6, u64::MAX] {
        let mut o = retained();
        assert!(
            o.export(sequence, [2, 0, 0, 0, 0, 0, 0, 0], |_| false)
                .is_err()
        );
        failed(&o);
    }
    let mut o = retained();
    o.sequence = u64::MAX;
    assert!(o.cancel(0).is_err());
    failed(&o);
    for identity in [0, 7, 0x1180, u64::MAX] {
        let mut o = Owner::new();
        assert!(o.begin(1, [identity; 8], 0).is_err());
        failed(&o);
    }
}
#[test]
fn copy_failure_unwind_and_cancellation_clear_every_result() {
    let mut o = retained();
    assert_eq!(
        o.export(5, [2, 0, 0, 0, 0, 0, 0, 0], |_| false),
        Err(Error::Copy)
    );
    failed(&o);
    let mut o = retained();
    assert!(
        catch_unwind(AssertUnwindSafe(|| o.export(
            5,
            [2, 0, 0, 0, 0, 0, 0, 0],
            |_| panic!("fixed copy seam")
        )))
        .is_err()
    );
    failed(&o);
    let mut o = retained();
    o.cancel(5).unwrap();
    clean(&o);
    assert_eq!(o.phase, Phase::Empty);
    let mut o = Owner::new();
    o.begin(1, [2; 8], 3).unwrap();
    o.start(2, 0).unwrap();
    o.update(3, 0, b"abc").unwrap();
    o.cancel(4).unwrap();
    clean(&o);
    let mut o = retained();
    o.quarantine();
    assert!(o.begin(5, [2; 8], 3).is_err());
    failed(&o);
}
