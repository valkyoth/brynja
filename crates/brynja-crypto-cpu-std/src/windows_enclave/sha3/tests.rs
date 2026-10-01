use super::*;
mod avx2;
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
struct Mock {
    fail: bool,
    sequence: u64,
    calls: std::vec::Vec<(usize, usize)>,
}
impl Channel for Mock {
    fn request(
        &mut self,
        request: Request,
        input: &[u8],
        _: Option<&mut [u8]>,
    ) -> Result<(), Error> {
        request.header(input)?;
        assert_eq!(self.sequence.checked_add(1), Some(request.sequence));
        self.sequence = request.sequence;
        self.calls.push((request.op, input.len()));
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
fn owner() -> Owner<Mock> {
    Owner {
        transport: Mock {
            fail: false,
            sequence: 0,
            calls: std::vec::Vec::new(),
        },
        state: State::Ready,
        sequence: 0,
        thread_bound: PhantomData,
    }
}
#[test]
fn setup_snapshots_and_failures_are_bound_to_sequence() -> Result<(), Error> {
    let name = [0xa5; 4097];
    let custom = [0x96; 8193];
    let mut owner = owner();
    owner.custom(
        Algorithm::Cshake128,
        Bits::new(&name, 8).map_err(|_| Error::Bounds)?,
        Bits::new(&custom, 8).map_err(|_| Error::Bounds)?,
    )?;
    assert_eq!(owner.transport.calls.first(), Some(&(28, 0)));
    assert_eq!(owner.transport.calls.last(), Some(&(31, 0)));
    assert_eq!(
        owner
            .transport
            .calls
            .iter()
            .filter(|(op, _)| *op == 29)
            .map(|(_, len)| len)
            .sum::<usize>(),
        name.len()
    );
    assert_eq!(
        owner
            .transport
            .calls
            .iter()
            .filter(|(op, _)| *op == 30)
            .map(|(_, len)| len)
            .sum::<usize>(),
        custom.len()
    );
    assert!(owner.transport.calls.iter().all(|(_, len)| *len <= 1024));
    owner.transport.fail = true;
    assert_eq!(
        owner.issue(
            Request {
                op: 22,
                ..Request::default()
            },
            &[],
            None
        ),
        Err(Error::Protocol)
    );
    assert_eq!(owner.state, State::Quarantined);
    assert_eq!(
        owner.issue(
            Request {
                op: 26,
                ..Request::default()
            },
            &[],
            None
        ),
        Err(Error::Quarantined)
    );
    Ok(())
}
#[test]
fn wire_rejects_shape_and_stale_receipts() -> Result<(), Error> {
    let base = Request {
        op: 22,
        sequence: 1,
        last: 8,
        ..Request::default()
    };
    base.header(b"abc")?;
    for request in [
        Request {
            sequence: 0,
            ..base
        },
        Request { op: 0, ..base },
        Request {
            algorithm: 1,
            ..base
        },
        Request { width: 1, ..base },
        Request {
            terminal: true,
            ..base
        },
        Request {
            name_bits: 1,
            ..base
        },
        Request {
            custom_bits: 1,
            ..base
        },
        Request { last: 0, ..base },
        Request { last: 9, ..base },
    ] {
        assert!(request.header(b"abc").is_err());
    }
    assert!(base.header(&[0; 1025]).is_err());
    let low = 0x10000;
    let valid = [low + 64, low + 512, 1, 1, 1, 0, 0];
    super::super::sha3_wire::receipt(low, 22, 3, valid)?;
    for index in 0..7 {
        let mut value = valid;
        let field = value.get_mut(index).ok_or(Error::Bounds)?;
        *field = 0;
        if index >= 5 {
            *field = 1;
        }
        assert!(super::super::sha3_wire::receipt(low, 22, 3, value).is_err());
    }
    let mut owner = owner();
    owner.sequence = u64::MAX;
    assert_eq!(owner.issue(base, b"abc", None), Err(Error::Exhausted));
    assert_eq!(owner.state, State::Quarantined);
    Ok(())
}
