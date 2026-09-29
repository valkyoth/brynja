use super::*;

struct Driver {
    fault: u8,
}
impl NativeDriver for Driver {
    fn run(&mut self, pending: &mut Pending<'_, '_, '_>) -> Result<Outcome, Error> {
        pending.native_request(0x1000, 0x2000)?;
        if self.fault == 1 {
            return pending.native_finish(false, [0; 4]);
        }
        let token = [9, 8, pending.session.epoch, 1, 0, 0, 0, 0];
        pending.native_exchange(0, &wire::encode(token), &[0; 32])?;
        let first = if self.fault == 4 {
            12
        } else if pending.exporting() {
            1
        } else {
            2
        };
        let mut second = token;
        second[4] = first;
        pending.native_exchange(
            if self.fault == 5 { 0 } else { 1 },
            &wire::encode(second),
            &[7; 32],
        )?;
        pending.native_finish(
            self.fault != 2,
            [first, 21, 1, if self.fault == 3 { 0 } else { 1 }],
        )
    }
}

#[test]
fn native_bridge_commit_copy_failure_and_cancel() {
    let mut session = Session::new();
    for fault in [0, 4, 0] {
        let mut output = [0xa5; 32];
        let result = session.execute(
            PublicInput::acknowledge(b"abc"),
            Disposition::ExportPublic(&mut output),
            &mut Driver { fault },
        );
        assert_eq!(
            result,
            if fault == 4 {
                Err(Error::Copy)
            } else {
                Ok(Outcome::Exported)
            }
        );
        assert_eq!(output, if fault == 4 { [0xa5; 32] } else { [7; 32] });
        assert_eq!(session.state(), State::Ready);
        assert_eq!(
            session.execute(
                PublicInput::acknowledge(b"abc"),
                Disposition::Cancel,
                &mut Driver { fault: 0 }
            ),
            Ok(Outcome::Cancelled)
        );
    }
}

#[test]
fn native_bridge_never_commits_uncertain_output_or_reuses_owner() {
    for fault in [1, 2, 3, 5] {
        let mut session = Session::new();
        let mut output = [0xa5; 32];
        assert!(
            session
                .execute(
                    PublicInput::acknowledge(b"abc"),
                    Disposition::ExportPublic(&mut output),
                    &mut Driver { fault }
                )
                .is_err()
        );
        assert_eq!(output, [0xa5; 32]);
        assert_eq!(session.state(), State::Quarantined);
        assert_eq!(
            session.execute(
                PublicInput::acknowledge(b"abc"),
                Disposition::Cancel,
                &mut Driver { fault: 0 }
            ),
            Err(Error::Quarantined)
        );
    }
}
