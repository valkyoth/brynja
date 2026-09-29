extern crate std;
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn produce(slot: &mut Slot<'_>, byte: u8) -> [u64; 4] {
    slot.fill(|out| {
        out.fill(byte);
        true
    })
    .unwrap()
}

#[test]
fn survives_worker_scope_and_metadata_move_then_exports_once() {
    let mut bytes = [0xa5; 32];
    {
        let mut owner = Slot::new(&mut bytes, [7, 9]).unwrap();
        let token = {
            let mut worker = [0x43; 64];
            let result = owner
                .fill(|out| {
                    out.copy_from_slice(&worker[..32]);
                    true
                })
                .unwrap();
            worker.fill(0);
            result
        };
        let mut moved = owner;
        assert_eq!(token, [7, 9, 1, 1]);
        assert_eq!(
            moved.fill(|_| panic!("overwrote live result")),
            Err(Error::Busy)
        );
        assert_eq!(
            moved.export_public(token, PUBLIC_OUTPUT, |data| {
                assert_eq!(data, &[0x43; 32]);
                true
            }),
            Ok(())
        );
        assert_eq!(moved.bytes, &[0; 32]);
        assert_eq!(
            moved.export_public(token, PUBLIC_OUTPUT, |_| panic!("replay")),
            Err(Error::Spent)
        );
        let next = produce(&mut moved, 5);
        assert_eq!(next, [7, 9, 2, 1]);
        assert_eq!(moved.cancel(next), Ok(()));
        assert_eq!(moved.bytes, &[0; 32]);
    }
    assert_eq!(bytes, [0; 32]);
}

#[test]
fn wrong_identity_generation_slot_and_public_flag_are_terminal() {
    for word in 0..4 {
        let mut bytes = [0; 32];
        let mut slot = Slot::new(&mut bytes, [7, 9]).unwrap();
        let good = produce(&mut slot, 4);
        let mut bad = good;
        bad[word] += 1;
        assert_eq!(
            slot.export_public(bad, PUBLIC_OUTPUT, |_| panic!("bad token")),
            Err(Error::Rejected)
        );
        assert_eq!(slot.bytes, &[0; 32]);
        assert_eq!(slot.cancel(good), Err(Error::Spent));
    }
    for flag in [0, PUBLIC_OUTPUT + 1] {
        let mut bytes = [0; 32];
        let mut slot = Slot::new(&mut bytes, [7, 9]).unwrap();
        let token = produce(&mut slot, 4);
        assert_eq!(
            slot.export_public(token, flag, |_| panic!("implicit export")),
            Err(Error::Rejected)
        );
        assert_eq!(slot.bytes, &[0; 32]);
        assert_eq!(slot.cancel(token), Err(Error::Spent));
    }
    let mut bytes = [0; 32];
    let mut slot = Slot::new(&mut bytes, [7, 9]).unwrap();
    let old = produce(&mut slot, 4);
    slot.cancel(old).unwrap();
    let current = produce(&mut slot, 5);
    assert_ne!(old, current);
    assert_eq!(
        slot.export_public(old, PUBLIC_OUTPUT, |_| panic!("stale export")),
        Err(Error::Rejected)
    );
    assert_eq!(slot.cancel(current), Err(Error::Spent));
}

#[test]
fn partial_fill_copy_and_unwind_clear_and_quarantine() {
    for unwind in [false, true] {
        for filling in [false, true] {
            let mut bytes = [0; 32];
            let mut slot = Slot::new(&mut bytes, [7, 9]).unwrap();
            let result = catch_unwind(AssertUnwindSafe(|| {
                if filling {
                    assert_eq!(
                        slot.fill(|out| {
                            out[..7].fill(0x77);
                            if unwind {
                                panic!("partial fill");
                            }
                            false
                        }),
                        Err(Error::Fill)
                    );
                } else {
                    let token = produce(&mut slot, 0x66);
                    let mut public = [0xa5; 32];
                    assert_eq!(
                        slot.export_public(token, PUBLIC_OUTPUT, |data| {
                            public[..7].copy_from_slice(&data[..7]);
                            if unwind {
                                panic!("partial copy");
                            }
                            false
                        }),
                        Err(Error::Copy)
                    );
                    assert_eq!(&public[..7], &[0x66; 7]);
                    assert_eq!(&public[7..], &[0xa5; 25]);
                }
            }));
            assert_eq!(result.is_err(), unwind);
            assert_eq!(slot.bytes, &[0; 32]);
            assert_eq!(
                slot.fill(|_| panic!("quarantined reuse")),
                Err(Error::Quarantined)
            );
            assert_eq!(slot.cancel([7, 9, 1, 1]), Err(Error::Quarantined));
        }
    }
}

#[test]
fn abandonment_cancellation_close_and_lost_completion_clear() {
    for action in 0..5 {
        let mut bytes = [0xa5; 32];
        {
            let mut slot = Slot::new(&mut bytes, [7, 9]).unwrap();
            let token = produce(&mut slot, 0x77);
            match action {
                0 => {
                    slot.cancel(token).unwrap();
                }
                1 => {
                    assert_eq!(slot.cancel([7, 9, 0, 1]), Err(Error::Rejected));
                }
                2 => {
                    slot.close();
                    slot.quarantine();
                    assert_eq!(slot.fill(|_| panic!("closed reuse")), Err(Error::Closed));
                }
                3 => {
                    slot.quarantine();
                    assert_eq!(
                        slot.export_public(token, PUBLIC_OUTPUT, |_| panic!("uncertain export")),
                        Err(Error::Quarantined)
                    );
                }
                _ => (), // Abandoned public token does not own the retained bytes.
            }
        }
        assert_eq!(bytes, [0; 32]);
    }
}

#[test]
fn generation_exhaustion_never_wraps_and_invalid_identity_clears() {
    let mut bytes = [0xa5; 32];
    assert!(matches!(
        Slot::new(&mut bytes, [0; 2]),
        Err(Error::Identity)
    ));
    assert_eq!(bytes, [0; 32]);
    let mut slot = Slot::new(&mut bytes, [7, 9]).unwrap();
    slot.generation = u64::MAX - 1;
    let token = produce(&mut slot, 1);
    assert_eq!(token[2], u64::MAX);
    slot.cancel(token).unwrap();
    assert_eq!(
        slot.fill(|_| panic!("wrapped generation")),
        Err(Error::Exhausted)
    );
    assert_eq!(slot.bytes, &[0; 32]);
    assert_eq!(
        slot.fill(|_| panic!("reopened exhausted")),
        Err(Error::Quarantined)
    );
}

#[test]
fn separate_instances_cannot_exchange_results() {
    let mut first = [0; 32];
    let mut second = [0; 32];
    let mut a = Slot::new(&mut first, [7, 9]).unwrap();
    let mut b = Slot::new(&mut second, [7, 10]).unwrap();
    let a_token = produce(&mut a, 1);
    let b_token = produce(&mut b, 2);
    assert_eq!(
        b.export_public(a_token, PUBLIC_OUTPUT, |_| panic!("cross instance")),
        Err(Error::Rejected)
    );
    assert_eq!(b.cancel(b_token), Err(Error::Spent));
    a.export_public(a_token, PUBLIC_OUTPUT, |data| {
        assert_eq!(data, &[1; 32]);
        true
    })
    .unwrap();
}
