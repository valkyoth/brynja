use super::*;
mod avx2;
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
#[cfg(all(
    feature = "strict-sha3-acceleration",
    target_os = "windows",
    target_arch = "x86_64",
    target_env = "msvc",
    not(miri),
    not(kani)
))]
mod native_avx2;
#[derive(Default)]
pub(super) struct Mock {
    calls: std::vec::Vec<(Request, usize)>,
    fail: bool,
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
            Err(Error::Protocol)
        } else {
            Ok(())
        }
    }
}
fn owner() -> Owner<Mock> {
    Owner {
        transport: Mock::default(),
        state: State::Ready,
        sequence: 0,
        thread_bound: PhantomData,
    }
}
#[test]
fn customization_snapshots_and_quarantine_are_bounded() -> Result<(), Error> {
    let mut o = owner();
    o.customization(Bits::new(&[1; 2049], 1).map_err(|_| Error::Bounds)?)?;
    assert_eq!(
        o.transport
            .calls
            .iter()
            .map(|(r, n)| (r.op, *n))
            .collect::<std::vec::Vec<_>>(),
        [(101, 1024), (101, 1024), (101, 1), (102, 0)]
    );
    o.transport.fail = true;
    assert_eq!(o.simple(107), Err(Error::Protocol));
    let count = o.transport.calls.len();
    assert_eq!(o.simple(107), Err(Error::Quarantined));
    assert_eq!(o.transport.calls.len(), count);
    Ok(())
}
#[test]
fn sequence_output_shape_and_failed_close_are_terminal() -> Result<(), Error> {
    let mut o = owner();
    o.sequence = u64::MAX;
    assert_eq!(o.simple(107), Err(Error::Exhausted));
    assert!(o.transport.calls.is_empty());
    let mut o = owner();
    assert_eq!(
        o.issue(
            Request {
                op: 106,
                algorithm: 1,
                width: 1,
                output_last: 8,
                ..Request::default()
            },
            &[],
            None
        ),
        Err(Error::Bounds)
    );
    assert!(o.transport.calls.is_empty());
    assert_eq!(o.state, State::Quarantined);
    o.transport.close_fail = true;
    assert_eq!(o.close(), Err(Error::Protocol));
    assert_eq!(o.state, State::Quarantined);
    o.transport.close_fail = false;
    o.close()?;
    assert_eq!(o.state, State::Closed);
    Ok(())
}
#[test]
fn receipt_rejects_counts_regions_and_wrong_operations() -> Result<(), Error> {
    use super::super::parallel_receipt::receipt;
    for op in 100..=108 {
        let length = usize::from(matches!(op, 101 | 103 | 104));
        let valid = [0x10040, 0x10200, 1, 1, length, usize::from(op == 106), 0];
        receipt(0x10000, op, length, valid)?;
        for i in 0..7 {
            let mut invalid = valid;
            let value = invalid.get_mut(i).ok_or(Error::Bounds)?;
            *value = if i < 2 {
                0
            } else {
                value.checked_add(1).ok_or(Error::Bounds)?
            };
            assert!(receipt(0x10000, op, length, invalid).is_err());
        }
    }
    assert!(receipt(0x10000, 99, 0, [0; 7]).is_err());
    assert!(receipt(0x10000, 109, 0, [0; 7]).is_err());
    receipt(0x10000, 0, 0, [0; 7])?;
    receipt(0x10000, 3, 0, [0; 7])?;
    Ok(())
}
