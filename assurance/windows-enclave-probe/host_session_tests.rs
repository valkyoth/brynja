extern crate std;
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn offer(epoch: u64, status: u64) -> [u8; 64] {
    wire::encode([7, 8, epoch, 1, status, 0, 0, 0])
}

fn begin(pending: &mut Pending<'_, '_, '_>) {
    let exporting = pending.exporting();
    let request = pending
        .enter(1000, if exporting { 2000 } else { 0 })
        .unwrap();
    assert_eq!(&request[..8], &2_u64.to_le_bytes());
    let command = wire::decode(&pending.offer(&offer(pending.session.epoch, 0)).unwrap());
    assert_eq!(&command[..4], &[7, 8, pending.session.epoch, 1]);
    assert_eq!(
        &command[4..],
        if exporting {
            &[1, 0x5055_424c_4943, 2000, 32]
        } else {
            &[2, 0, 0, 0]
        }
    );
}

#[test]
fn success_cancel_and_copy_failure_reuse_only_after_complete_cleanup() {
    let mut session = Session::new();
    for index in 1..=12 {
        let mut output = [0xa5; 32];
        let public = index % 3 != 0;
        let disposition = if public {
            Disposition::ExportPublic(&mut output)
        } else {
            Disposition::Cancel
        };
        let mut pending = session
            .prepare(PublicInput::acknowledge(b"abc"), disposition)
            .unwrap();
        begin(&mut pending);
        let status = if !public {
            2
        } else if index % 3 == 1 {
            1
        } else {
            12
        };
        if public {
            pending
                .receive_public(if status == 1 { &[9; 32] } else { &[9; 7] })
                .unwrap();
        }
        assert_eq!(pending.session.epoch, index);
        pending.offer(&offer(index, status)).unwrap();
        let expected = match status {
            1 => Ok(Outcome::Exported),
            2 => Ok(Outcome::Cancelled),
            _ => Err(Error::Copy),
        };
        assert_eq!(pending.finish(status, 21, true, true), expected);
        assert_eq!(pending.staging, [0; 32]);
        drop(pending);
        assert_eq!(output, if status == 1 { [9; 32] } else { [0xa5; 32] });
        assert_eq!(session.state(), State::Ready);
    }
}

#[test]
fn aborted_or_unwinding_exchange_quarantines_and_never_commits() {
    for stage in 0..4 {
        for unwind in [false, true] {
            let mut session = Session::new();
            let mut output = [0xa5; 32];
            let result = catch_unwind(AssertUnwindSafe(|| {
                let mut pending = session
                    .prepare(
                        PublicInput::acknowledge(b"abc"),
                        Disposition::ExportPublic(&mut output),
                    )
                    .unwrap();
                pending.enter(1000, 2000).unwrap();
                if stage >= 1 {
                    pending.offer(&offer(1, 0)).unwrap();
                }
                if stage >= 2 {
                    pending.receive_public(&[9; 32]).unwrap();
                }
                if stage >= 3 {
                    pending.offer(&offer(1, 1)).unwrap();
                }
                if unwind {
                    panic!("public test unwind");
                }
            }));
            assert_eq!(result.is_err(), unwind);
            assert_eq!(output, [0xa5; 32]);
            assert_eq!(session.state(), State::Quarantined);
            assert!(matches!(
                session.prepare(PublicInput::acknowledge(b"abc"), Disposition::Cancel),
                Err(Error::Quarantined)
            ));
        }
    }
}

#[test]
fn unentered_drop_is_reusable_but_forgotten_scope_latches_busy() {
    let mut session = Session::new();
    drop(
        session
            .prepare(PublicInput::acknowledge(b""), Disposition::Cancel)
            .unwrap(),
    );
    assert_eq!(session.state(), State::Ready);
    assert_eq!(session.epoch, 0);
    for entered in [false, true] {
        let mut session = Session::new();
        let mut pending = session
            .prepare(PublicInput::acknowledge(b""), Disposition::Cancel)
            .unwrap();
        if entered {
            begin(&mut pending);
        }
        core::mem::forget(pending);
        assert_eq!(session.state(), State::Busy);
        assert!(matches!(
            session.prepare(PublicInput::acknowledge(b""), Disposition::Cancel),
            Err(Error::Busy)
        ));
    }
}

#[test]
fn stale_future_and_changed_identity_quarantine() {
    for token in [
        [7, 8, 0, 1],
        [7, 8, 2, 1],
        [7, 8, u64::MAX, 1],
        [9, 8, 1, 1],
        [7, 9, 1, 1],
        [0, 0, 1, 1],
        [7, 8, 1, 0],
        [7, 8, 1, 2],
    ] {
        let mut session = Session::new();
        session.namespace = Some([7, 8]);
        let mut pending = session
            .prepare(PublicInput::acknowledge(b"abc"), Disposition::Cancel)
            .unwrap();
        pending.enter(1000, 0).unwrap();
        assert_eq!(
            pending.offer(&wire::encode([
                token[0], token[1], token[2], token[3], 0, 0, 0, 0
            ])),
            Err(Error::Protocol)
        );
        drop(pending);
        assert_eq!(session.state(), State::Quarantined);
    }
}

#[test]
fn missing_spent_or_cleanup_confirmation_never_commits() {
    for (second, inner, outer) in [
        (0, true, true),
        (1, true, true),
        (2, true, true),
        (21, false, true),
        (21, true, false),
        (21, false, false),
    ] {
        let mut session = Session::new();
        let mut output = [0xa5; 32];
        let mut pending = session
            .prepare(
                PublicInput::acknowledge(b"abc"),
                Disposition::ExportPublic(&mut output),
            )
            .unwrap();
        begin(&mut pending);
        pending.receive_public(&[9; 32]).unwrap();
        pending.offer(&offer(1, 1)).unwrap();
        assert_eq!(
            pending.finish(1, second, inner, outer),
            Err(Error::Protocol)
        );
        assert_eq!(pending.staging, [0; 32]);
        drop(pending);
        assert_eq!(output, [0xa5; 32]);
        assert_eq!(session.state(), State::Quarantined);
    }
}

#[test]
fn incomplete_duplicate_and_out_of_order_responses_fail() {
    for index in 0..9 {
        let mut session = Session::new();
        let mut output = [0xa5; 32];
        let mut pending = session
            .prepare(
                PublicInput::acknowledge(b"abc"),
                Disposition::ExportPublic(&mut output),
            )
            .unwrap();
        match index {
            0 => {
                assert_eq!(pending.offer(&offer(1, 0)), Err(Error::Protocol));
            }
            1 => {
                assert_eq!(pending.finish(1, 21, true, true), Err(Error::Protocol));
            }
            2 => {
                begin(&mut pending);
                assert_eq!(pending.offer(&offer(2, 1)), Err(Error::Protocol));
            }
            3 => {
                begin(&mut pending);
                assert_eq!(pending.offer(&offer(1, 2)), Err(Error::Protocol));
            }
            4 => {
                begin(&mut pending);
                pending.receive_public(&[9; 7]).unwrap();
                pending.offer(&offer(1, 1)).unwrap();
                assert_eq!(pending.finish(1, 21, true, true), Err(Error::Protocol));
            }
            5 => {
                begin(&mut pending);
                pending.receive_public(&[9; 32]).unwrap();
                assert_eq!(pending.receive_public(&[9; 32]), Err(Error::Protocol));
            }
            6 => {
                begin(&mut pending);
                pending.offer(&offer(1, 1)).unwrap();
                assert_eq!(pending.finish(1, 21, true, true), Err(Error::Protocol));
            }
            7 => {
                begin(&mut pending);
                let mut wrong = offer(1, 1);
                wrong[63] = 1;
                assert_eq!(pending.offer(&wrong), Err(Error::Protocol));
            }
            _ => {
                begin(&mut pending);
                pending.offer(&offer(1, 1)).unwrap();
                assert_eq!(pending.offer(&offer(1, 1)), Err(Error::Protocol));
            }
        }
        drop(pending);
        assert_eq!(output, [0xa5; 32]);
        assert_eq!(session.state(), State::Quarantined);
    }
}

#[test]
fn checked_admission_and_all_lengths_match_wire_snapshot() {
    let mut session = Session::new();
    for length in 0..=1024 {
        let input = [0x7c; 1024];
        let mut pending = session
            .prepare(
                PublicInput::acknowledge(&input[..length]),
                Disposition::Cancel,
            )
            .unwrap();
        let request = pending.enter(1000, 0).unwrap();
        assert_eq!(
            u64::from_le_bytes(request[16..24].try_into().unwrap()),
            length as u64
        );
        assert_eq!(&request[48..48 + length], &input[..length]);
        assert!(request[48 + length..].iter().all(|byte| *byte == 0));
        pending.offer(&offer(length as u64 + 1, 0)).unwrap();
        pending.offer(&offer(length as u64 + 1, 2)).unwrap();
        assert_eq!(pending.finish(2, 21, true, true), Ok(Outcome::Cancelled));
    }
    assert!(matches!(
        session.prepare(PublicInput::acknowledge(&[0; 1025]), Disposition::Cancel),
        Err(Error::Bounds)
    ));
    assert_eq!(session.state(), State::Ready);
    session.epoch = u64::MAX - 1;
    {
        let mut pending = session
            .prepare(PublicInput::acknowledge(b""), Disposition::Cancel)
            .unwrap();
        begin(&mut pending);
        assert_eq!(pending.session.epoch, u64::MAX);
        pending.offer(&offer(u64::MAX, 2)).unwrap();
        assert_eq!(pending.finish(2, 21, true, true), Ok(Outcome::Cancelled));
    }
    for _ in 0..2 {
        assert!(matches!(
            session.prepare(PublicInput::acknowledge(b""), Disposition::Cancel),
            Err(Error::Exhausted)
        ));
        assert_eq!(session.epoch, u64::MAX);
    }
    for command in [0, u64::MAX - 63, u64::MAX] {
        let mut session = Session::new();
        let mut pending = session
            .prepare(PublicInput::acknowledge(b""), Disposition::Cancel)
            .unwrap();
        assert_eq!(pending.enter(command, 0), Err(Error::Protocol));
    }
}
