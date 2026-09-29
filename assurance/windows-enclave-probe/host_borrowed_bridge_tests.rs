use super::*;

#[test]
fn descriptor_is_metadata_only_and_borrows_original_input() {
    for length in 0..=1024 {
        let data = [0x5a; 1024];
        let input = &data[..length];
        let mut session = Session::new();
        let mut pending = session
            .prepare(PublicInput::acknowledge(input), Disposition::Cancel)
            .unwrap();
        let request = pending.native_request(4096, 0).unwrap();
        assert_eq!(core::mem::size_of_val(&request), 64);
        assert_eq!(
            wire::decode(request.metadata()),
            [
                3,
                0,
                length as u64,
                if length == 0 {
                    0
                } else {
                    input.as_ptr() as u64
                },
                4096,
                64,
                0,
                0,
            ]
        );
        assert_eq!(pending.session.epoch, 1);
        assert!(pending.phase == Phase::Entered);
        // A separate mutable ledger callback is possible without releasing input.
        let offer = wire::encode([7, 8, 1, 1, 0, 0, 0, 0]);
        pending.native_exchange(0, &offer, &[0; 32]).unwrap();
        assert_eq!(wire::decode(request.metadata())[2], length as u64);
        assert!(pending.native_request(4096, 0).is_err());
        assert_eq!(pending.session.state(), State::Quarantined);
    }
}

#[test]
fn malformed_entry_never_becomes_reusable_or_burns_epoch() {
    for (command, output) in [(0, 4096), (u64::MAX, 4096), (4096, 0), (4096, u64::MAX)] {
        let mut session = Session::new();
        let mut destination = [0xa5; 32];
        {
            let mut pending = session
                .prepare(
                    PublicInput::acknowledge(b"abc"),
                    Disposition::ExportPublic(&mut destination),
                )
                .unwrap();
            assert!(pending.native_request(command, output).is_err());
            assert_eq!(pending.session.epoch, 0);
        }
        assert_eq!(destination, [0xa5; 32]);
        assert_eq!(session.state(), State::Quarantined);
    }
}

#[test]
fn entered_scope_drop_quarantines_and_forgetting_stays_busy() {
    let mut session = Session::new();
    {
        let mut pending = session
            .prepare(PublicInput::acknowledge(b"x"), Disposition::Cancel)
            .unwrap();
        let _request = pending.native_request(4096, 0).unwrap();
    }
    assert_eq!(session.state(), State::Quarantined);
    let mut session = Session::new();
    let mut pending = session
        .prepare(PublicInput::acknowledge(b"x"), Disposition::Cancel)
        .unwrap();
    let request = pending.native_request(4096, 0).unwrap();
    core::mem::forget(pending);
    assert_eq!(wire::decode(request.metadata())[2], 1);
    assert_eq!(session.state(), State::Busy);
}
