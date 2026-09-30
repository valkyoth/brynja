use super::*;
#[cfg(not(all(
    target_os = "windows",
    target_arch = "x86_64",
    target_env = "msvc",
    not(miri),
    not(kani)
)))]
mod lifecycle;
#[cfg(all(
    target_os = "windows",
    target_arch = "x86_64",
    target_env = "msvc",
    not(miri),
    not(kani)
))]
mod native;
#[derive(Default)]
pub(super) struct Mock {
    calls: std::vec::Vec<(Request, usize)>,
    fail: bool,
    panic: bool,
    close_fail: bool,
}
impl Channel for Mock {
    fn request(
        &mut self,
        request: Request,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<(), Error> {
        self.calls.push((request, input.len()));
        assert!(!self.panic, "injected transport unwind");
        if let Some(output) = output {
            output.fill(0x5a);
        }
        if self.fail {
            Err(Error::Protocol)
        } else {
            Ok(())
        }
    }
    fn close(&mut self) -> Result<(), Error> {
        if self.close_fail {
            Err(Error::Release)
        } else {
            Ok(())
        }
    }
}
#[test]
fn receipt_counts_and_regions_reject_mutations() -> Result<(), Error> {
    use super::super::sha2_batch_receipt::receipt;
    for op in 80..=86 {
        let length = usize::from(matches!(op, 82 | 83));
        let valid = [0x10040, 0x10200, 1, 1, length, usize::from(op == 85), 0];
        receipt(0x10000, op, length, valid)?;
        for i in 0..7 {
            let mut bad = valid;
            let value = bad.get_mut(i).ok_or(Error::Bounds)?;
            *value = if i < 2 {
                0
            } else {
                value.checked_add(1).ok_or(Error::Bounds)?
            };
            assert!(receipt(0x10000, op, length, bad).is_err());
        }
        let mut overlap = valid;
        *overlap.get_mut(1).ok_or(Error::Bounds)? = 0x10080;
        assert!(receipt(0x10000, op, length, overlap).is_err());
        assert!(receipt(usize::MAX, op, length, valid).is_err());
        assert!(receipt(0x10000, op, 1025, valid).is_err());
    }
    for op in [0, 3] {
        receipt(0x10000, op, 0, [0; 7])?;
        assert!(receipt(0x10000, op, 0, [1; 7]).is_err());
    }
    Ok(())
}
#[test]
fn transport_failure_and_exhaustion_stay_terminal() -> Result<(), Error> {
    let mut owner = Owner {
        transport: Mock::default(),
        state: State::Ready,
        sequence: u64::MAX,
        thread_bound: PhantomData,
    };
    let request = Request {
        op: 80,
        plan: [2; 8],
        ..Request::default()
    };
    assert_eq!(owner.issue(request, &[], None), Err(Error::Exhausted));
    assert!(owner.transport.calls.is_empty());
    assert_eq!(owner.state, State::Quarantined);
    owner.transport.close_fail = true;
    assert_eq!(owner.close(), Err(Error::Release));
    assert_eq!(owner.state, State::Quarantined);
    owner.transport.close_fail = false;
    owner.close()?;
    assert_eq!(owner.state, State::Closed);
    assert_eq!(owner.issue(request, &[], None), Err(Error::Quarantined));
    Ok(())
}
