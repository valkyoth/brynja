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
        Ok(())
    }
}
#[test]
fn streamed_customization_and_failures_are_bounded() -> Result<(), Error> {
    let mut owner = Owner {
        transport: Mock::default(),
        state: State::Ready,
        sequence: 0,
        thread_bound: PhantomData,
    };
    let custom = [1; 2049];
    owner.begin(
        Algorithm::TupleHash128,
        Bits::new(&custom, 1).map_err(|_| Error::Bounds)?,
    )?;
    let first = owner.transport.calls.first().ok_or(Error::Protocol)?.0;
    assert_eq!(first.custom_bits, 16385);
    assert_eq!(first.op, 60);
    assert_eq!(
        owner.transport.calls.last().ok_or(Error::Protocol)?.0.op,
        62
    );
    assert!(owner.transport.calls.iter().all(|(_, n)| *n <= 1024));
    owner.transport.fail = true;
    assert_eq!(owner.simple(65), Err(Error::Protocol));
    assert_eq!(owner.state, State::Quarantined);
    let count = owner.transport.calls.len();
    assert_eq!(owner.simple(70), Err(Error::Quarantined));
    assert_eq!(owner.transport.calls.len(), count);
    Ok(())
}

#[test]
fn empty_customization_does_not_reenter_completed_setup() -> Result<(), Error> {
    let mut owner = Owner {
        transport: Mock::default(),
        state: State::Ready,
        sequence: 0,
        thread_bound: PhantomData,
    };
    owner.begin(
        Algorithm::TupleHash128,
        Bits::new(&[], 0).map_err(|_| Error::Bounds)?,
    )?;
    assert_eq!(
        owner
            .transport
            .calls
            .iter()
            .map(|(r, _)| r.op)
            .collect::<std::vec::Vec<_>>(),
        [60, 62]
    );
    owner.chunks(64, Bits::new(&[], 0).map_err(|_| Error::Bounds)?)?;
    assert_eq!(
        owner.transport.calls.last().ok_or(Error::Protocol)?.0.op,
        64
    );
    Ok(())
}
#[test]
fn receipt_rejects_changed_counts_and_regions() -> Result<(), Error> {
    for op in 60..=70 {
        let length = usize::from(matches!(op, 61 | 64));
        let valid = [0x10040, 0x10200, 1, 1, length, usize::from(op == 68), 0];
        super::super::tuple_receipt::receipt(0x10000, op, length, valid)?;
        for i in 0..7 {
            let mut invalid = valid;
            let value = invalid.get_mut(i).ok_or(Error::Bounds)?;
            *value = if i < 2 {
                0
            } else {
                value.checked_add(1).ok_or(Error::Bounds)?
            };
            assert!(super::super::tuple_receipt::receipt(0x10000, op, length, invalid).is_err());
        }
    }
    Ok(())
}
