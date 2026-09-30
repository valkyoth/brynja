use super::*;
fn session() -> Session {
    Session(Owner {
        transport: Transport(Mock::default()),
        state: State::Ready,
        sequence: 0,
        thread_bound: PhantomData,
    })
}
fn empty() -> Result<Bits<'static>, Error> {
    Bits::new(&[], 0).map_err(|_| Error::Bounds)
}
#[test]
fn abandon_forget_cancel_and_close_preserve_ownership() -> Result<(), Error> {
    let mut s = session();
    drop(s.stream(Algorithm::ParallelHash128, 8, empty()?, 10)?);
    assert_eq!(s.state(), State::Quarantined);
    s.close()?;
    assert_eq!(s.state(), State::Closed);
    let mut s = session();
    core::mem::forget(s.stream(Algorithm::ParallelHash128, 8, empty()?, 10)?);
    assert!(matches!(
        s.stream(Algorithm::ParallelHash128, 8, empty()?, 10),
        Err(Error::Busy)
    ));
    s.close()?;
    let mut s = session();
    s.stream(Algorithm::ParallelHash128, 8, empty()?, 10)?
        .cancel()?;
    assert_eq!(s.state(), State::Ready);
    Ok(())
}
#[test]
fn byte_updates_partial_tail_and_public_commit_are_transactional() -> Result<(), Error> {
    let mut s = session();
    let mut stream = s.stream(Algorithm::ParallelHash128, 7, empty()?, 10000)?;
    stream.update(&[1; 2049])?;
    let retained = stream.finalize(Bits::new(&[1; 2049], 1).map_err(|_| Error::Bounds)?, 33, 3)?;
    retained.loan.session.0.transport.0.fail = true;
    let mut output = [0xa5; 33];
    assert!(matches!(
        retained.declassify(&mut output, PublicDeclassification::acknowledge()),
        Err(Error::Protocol)
    ));
    assert_eq!(output, [0xa5; 33]);
    assert_eq!(s.state(), State::Quarantined);
    let calls = &s.0.transport.0.calls;
    assert!(calls.iter().all(|(_, n)| *n <= 1024));
    let finish = calls
        .iter()
        .find(|(r, _)| r.op == 104)
        .ok_or(Error::Protocol)?;
    assert_eq!(
        (
            finish.1,
            finish.0.last,
            finish.0.width,
            finish.0.output_last
        ),
        (1, 1, 33, 3)
    );
    Ok(())
}
#[test]
fn retained_composition_and_xof_fragments_do_not_export_implicitly() -> Result<(), Error> {
    let mut s = session();
    {
        let reader = s
            .stream(Algorithm::ParallelHashXof128, 8, empty()?, 10)?
            .finalize_xof(empty()?)?;
        let reader = reader
            .retain(0, 0, false)?
            .declassify(&mut [], PublicDeclassification::acknowledge())?
            .ok_or(Error::Protocol)?;
        let retained = reader.retain(3, 3, true)?;
        let finalized = retained.rehash(Algorithm::ParallelHash256, 1, empty()?, 3, (32, 8))?;
        let Finalized::Digest(retained) = finalized else {
            return Err(Error::Protocol);
        };
        assert_eq!(
            retained
                .loan
                .session
                .0
                .transport
                .0
                .calls
                .iter()
                .filter(|(r, _)| r.op == 106)
                .count(),
            1
        );
        retained.cancel()?;
    }
    assert_eq!(s.state(), State::Ready);
    let r = s
        .stream(Algorithm::ParallelHash128, 8, empty()?, 0)?
        .finalize(empty()?, 0, 0)?;
    assert!(
        r.declassify(&mut [], PublicDeclassification::acknowledge())?
            .is_none()
    );
    Ok(())
}
#[test]
fn wrong_domains_and_invalid_parameters_never_permit_reuse() -> Result<(), Error> {
    let mut s = session();
    assert!(matches!(
        s.stream(Algorithm::ParallelHash128, 0, empty()?, 10),
        Err(Error::Bounds)
    ));
    assert_eq!(s.state(), State::Quarantined);
    for algorithm in [Algorithm::ParallelHash128, Algorithm::ParallelHashXof128] {
        let mut s = session();
        let stream = s.stream(algorithm, 8, empty()?, 10)?;
        if algorithm.fixed() {
            assert!(matches!(stream.finalize_xof(empty()?), Err(Error::Bounds)));
        } else {
            assert!(matches!(
                stream.finalize(empty()?, 32, 8),
                Err(Error::Bounds)
            ));
        }
        assert_eq!(s.state(), State::Quarantined);
    }
    Ok(())
}
