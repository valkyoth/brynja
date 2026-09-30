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
fn abandoned_and_forgotten_loans_never_release_parent() -> Result<(), Error> {
    let mut s = session();
    drop(s.stream(Algorithm::TupleHash128, empty()?)?);
    assert_eq!(s.state(), State::Quarantined);
    s.close()?;
    assert_eq!(s.state(), State::Closed);
    let mut s = session();
    core::mem::forget(s.stream(Algorithm::TupleHash128, empty()?)?);
    assert!(matches!(
        s.stream(Algorithm::TupleHash128, empty()?),
        Err(Error::Busy)
    ));
    s.close()?;
    let mut s = session();
    let mut stream = s.stream(Algorithm::TupleHash128, empty()?)?;
    drop(stream.item(0)?);
    assert!(matches!(stream.finalize(1, 8), Err(Error::Quarantined)));
    assert_eq!(s.state(), State::Quarantined);
    Ok(())
}

#[test]
fn forgotten_item_is_rejected_before_backend_entry() -> Result<(), Error> {
    for algorithm in [Algorithm::TupleHash128, Algorithm::TupleHashXof128] {
        let mut s = session();
        let mut stream = s.stream(algorithm, empty()?)?;
        core::mem::forget(stream.item(1)?);
        let calls = stream.0.session.0.transport.0.calls.len();
        assert!(matches!(stream.item(0), Err(Error::Busy)));
        if algorithm.fixed() {
            assert!(matches!(stream.finalize(32, 8), Err(Error::Bounds)));
        } else {
            assert!(matches!(stream.finalize_xof(), Err(Error::Bounds)));
        }
        assert_eq!(s.0.transport.0.calls.len(), calls);
        assert_eq!(s.state(), State::Quarantined);
        s.close()?;
    }
    Ok(())
}
#[test]
fn item_snapshots_and_export_failure_are_transactional() -> Result<(), Error> {
    let mut s = session();
    let mut stream = s.stream(Algorithm::TupleHash128, empty()?)?;
    let mut item = stream.item(16385)?;
    item.update(Bits::new(&[1; 2049], 1).map_err(|_| Error::Bounds)?)?;
    item.finish()?;
    let result = stream.finalize(32, 8)?;
    result.loan.session.0.transport.0.fail = true;
    let mut destination = [0xa5; 32];
    assert!(matches!(
        result.declassify(&mut destination, PublicDeclassification::acknowledge()),
        Err(Error::Protocol)
    ));
    assert_eq!(destination, [0xa5; 32]);
    assert_eq!(s.state(), State::Quarantined);
    assert!(s.0.transport.0.calls.iter().all(|(_, n)| *n <= 1024));
    Ok(())
}
#[test]
fn xof_rehash_cancel_and_empty_results_preserve_ownership() -> Result<(), Error> {
    let mut s = session();
    let reader = s
        .stream(Algorithm::TupleHashXof128, empty()?)?
        .finalize_xof()?;
    let retained = reader.retain(2, 8, false)?;
    let mut out = [0; 2];
    let reader = retained
        .declassify(&mut out, PublicDeclassification::acknowledge())?
        .ok_or(Error::Protocol)?;
    assert_eq!(out, [0x5a; 2]);
    let result = reader.retain(1, 3, true)?;
    result.rehash(Algorithm::TupleHash256, empty()?)?.cancel()?;
    assert_eq!(s.state(), State::Ready);
    let result = s
        .stream(Algorithm::TupleHash128, empty()?)?
        .finalize(0, 0)?;
    assert!(
        result
            .declassify(&mut [], PublicDeclassification::acknowledge())?
            .is_none()
    );
    assert_eq!(s.state(), State::Ready);
    Ok(())
}
