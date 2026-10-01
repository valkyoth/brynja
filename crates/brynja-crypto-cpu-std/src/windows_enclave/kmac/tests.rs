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
    feature = "strict-kmac-acceleration",
    target_os = "windows",
    target_arch = "x86_64",
    target_env = "msvc",
    not(miri),
    not(kani)
))]
mod native_avx2;
#[derive(Default)]
struct Mock {
    fail: bool,
    close_fails: bool,
    decision: u8,
    sequence: u64,
    calls: std::vec::Vec<(Request, usize)>,
}
impl Channel for Mock {
    fn request(
        &mut self,
        request: Request,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<(), Error> {
        request.header(input)?;
        assert_eq!(self.sequence.checked_add(1), Some(request.sequence));
        self.sequence = request.sequence;
        assert_eq!(output.as_ref().map(|v| v.len()), request.output_width());
        self.calls.push((request, input.len()));
        if let Some(output) = output {
            output.fill(self.decision);
        }
        if self.fail {
            Err(Error::Protocol)
        } else {
            Ok(())
        }
    }
    fn close(&mut self) -> Result<(), Error> {
        if self.close_fails {
            Err(Error::Release)
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
fn bits(input: &[u8], last: u8) -> Result<Bits<'_>, Error> {
    Bits::new(input, last).map_err(|_| Error::Bounds)
}
#[test]
fn setup_streaming_snapshots_bind_key_customization_and_sequence() -> Result<(), Error> {
    for algorithm in [
        Algorithm::Kmac128,
        Algorithm::Kmac256,
        Algorithm::KmacXof128,
        Algorithm::KmacXof256,
    ] {
        let mut o = owner();
        let key = [1; 4097];
        let custom = [1; 8193];
        o.begin(algorithm, bits(&key, 1)?, bits(&custom, 1)?)?;
        let first = o.transport.calls.first().ok_or(Error::Protocol)?.0;
        assert_eq!(first.op, 40);
        assert_eq!(first.algorithm, algorithm.wire());
        assert_eq!(first.key_bits, 32769);
        assert_eq!(first.custom_bits, 65537);
        assert_eq!(o.transport.calls.last().ok_or(Error::Protocol)?.0.op, 44);
        for (op, length) in [(41, custom.len()), (43, key.len())] {
            assert_eq!(
                o.transport
                    .calls
                    .iter()
                    .filter(|(r, _)| r.op == op)
                    .map(|(_, n)| n)
                    .sum::<usize>(),
                length
            );
            assert_eq!(
                o.transport
                    .calls
                    .iter()
                    .rev()
                    .find(|(r, _)| r.op == op)
                    .ok_or(Error::Protocol)?
                    .0
                    .last,
                1
            );
        }
        assert!(o.transport.calls.iter().all(|(_, n)| *n <= 1024));
        o.transport.fail = true;
        assert_eq!(o.simple(45), Err(Error::Protocol));
        assert_eq!(o.state, State::Quarantined);
        let count = o.transport.calls.len();
        assert_eq!(o.simple(51), Err(Error::Quarantined));
        assert_eq!(o.transport.calls.len(), count);
    }
    Ok(())
}
#[test]
fn verification_decisions_fail_closed_on_invalid_or_failed_receipts() -> Result<(), Error> {
    for decision in [0, 1, 2, 255] {
        let mut o = owner();
        o.transport.decision = decision;
        let result = o.verify(Algorithm::Kmac128, bits(&[0; 32], 8)?);
        if decision <= 1 {
            assert_eq!(result, Ok(decision == 1));
            assert_eq!(o.state, State::Ready);
        } else {
            assert_eq!(result, Err(Error::Protocol));
            assert_eq!(o.state, State::Quarantined);
        }
    }
    let mut o = owner();
    o.transport.decision = 1;
    o.transport.fail = true;
    assert_eq!(
        o.verify(Algorithm::Kmac128, bits(&[0; 32], 8)?),
        Err(Error::Protocol)
    );
    assert_eq!(o.state, State::Quarantined);
    o.transport.close_fails = true;
    assert_eq!(o.close(), Err(Error::Release));
    assert_eq!(o.state, State::Quarantined);
    o.transport.close_fails = false;
    o.close()?;
    assert_eq!(o.state, State::Closed);
    o.close()?;
    Ok(())
}
#[test]
fn wire_and_receipts_reject_wrong_operations_shapes_counts_and_regions() -> Result<(), Error> {
    let base = Request {
        op: 45,
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
        Request { op: 39, ..base },
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
            key_bits: 1,
            ..base
        },
        Request {
            custom_bits: 1,
            ..base
        },
        Request { last: 7, ..base },
    ] {
        assert!(request.header(b"abc").is_err());
    }
    assert!(base.header(&[0; 1025]).is_err());
    for operation in 40..=51 {
        let length = usize::from(matches!(operation, 41 | 43 | 45 | 46 | 49));
        let low = 0x10000;
        let valid = [
            low + 64,
            low + 512,
            1,
            1,
            length,
            usize::from(matches!(operation, 48 | 49)),
            0,
        ];
        super::super::kmac_wire::receipt(low, operation, length, valid)?;
        for index in 0..7 {
            let mut invalid = valid;
            let value = invalid.get_mut(index).ok_or(Error::Bounds)?;
            *value = value.checked_add(1).ok_or(Error::Bounds)?;
            if index < 2 {
                *value = 0;
            }
            assert!(super::super::kmac_wire::receipt(low, operation, length, invalid).is_err());
        }
        let mut overlap = valid;
        *overlap.get_mut(1).ok_or(Error::Bounds)? = low + 64;
        assert!(super::super::kmac_wire::receipt(low, operation, length, overlap).is_err());
    }
    let mut o = owner();
    o.sequence = u64::MAX;
    assert_eq!(o.issue(base, b"abc", None), Err(Error::Exhausted));
    assert_eq!(o.state, State::Quarantined);
    let mut o = owner();
    assert_eq!(
        o.issue(
            Request {
                op: 49,
                algorithm: 1,
                last: 8,
                ..Request::default()
            },
            &[0; 32],
            None
        ),
        Err(Error::Bounds)
    );
    assert!(o.transport.calls.is_empty());
    Ok(())
}
