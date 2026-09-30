use super::*;
fn session() -> Session {
    Session(Owner {
        transport: Transport(Mock::default()),
        state: State::Ready,
        sequence: 0,
        thread_bound: PhantomData,
    })
}
fn plan() -> Result<Plan, Error> {
    Plan::new([
        Some(Algorithm::SHA256),
        None,
        Some(Algorithm::SHA512),
        None,
        None,
        None,
        None,
        None,
    ])
}
fn complete(s: &mut Session) -> Result<Retained<'_>, Error> {
    let mut batch = s.batch(plan()?, 0)?;
    batch.item()?.finish()?;
    batch.item()?.finish()?;
    batch.seal()
}
#[test]
fn ordered_slots_chunking_and_seal_are_exact() -> Result<(), Error> {
    assert!(Plan::new([None; 8]).is_err());
    let mut s = session();
    let mut batch = s.batch(plan()?, 4099)?;
    let mut first = batch.item()?;
    assert_eq!(first.slot(), 0);
    first.update(&[1; 2049])?;
    first.finish_bits(&[0x80; 2049], 1)?;
    let second = batch.item()?;
    assert_eq!(second.slot(), 2);
    second.finish()?;
    assert!(matches!(batch.item(), Err(Error::Bounds)));
    let result = batch.seal()?;
    assert_eq!(result.plan(), plan()?);
    let mut out = [0; 512];
    result.declassify(&mut out, PublicDeclassification::acknowledge())?;
    assert_eq!(out, [0x5a; 512]);
    assert_eq!(s.state(), State::Ready);
    assert!(s.0.transport.0.calls.iter().all(|(_, n)| *n <= 1024));
    let updates: std::vec::Vec<_> =
        s.0.transport
            .0
            .calls
            .iter()
            .filter(|(r, _)| r.op == 82)
            .map(|(_, n)| *n)
            .collect();
    assert_eq!(updates, [1024, 1024, 1, 1024, 1024]);
    s.batch(plan()?, 0)?.cancel()?;
    complete(&mut s)?.cancel()?;
    assert_eq!(s.state(), State::Ready);
    Ok(())
}
#[test]
fn forgotten_item_cannot_seal_or_start_another_slot() -> Result<(), Error> {
    let mut s = session();
    let mut batch = s.batch(plan()?, 0)?;
    core::mem::forget(batch.item()?);
    let calls = batch.0.session.0.transport.0.calls.len();
    assert!(matches!(batch.item(), Err(Error::Busy)));
    assert!(matches!(batch.seal(), Err(Error::Bounds)));
    assert_eq!(s.0.transport.0.calls.len(), calls);
    assert_eq!(s.state(), State::Quarantined);
    s.close()?;
    let mut s = session();
    let mut batch = s.batch(plan()?, 0)?;
    core::mem::forget(batch.item()?);
    batch.cancel()?;
    assert_eq!(s.state(), State::Ready);
    Ok(())
}
#[test]
fn early_seal_abandonment_and_forgetting_retain_ownership() -> Result<(), Error> {
    let mut s = session();
    assert!(matches!(s.batch(plan()?, 0)?.seal(), Err(Error::Bounds)));
    assert_eq!(s.state(), State::Quarantined);
    s.close()?;
    let mut s = session();
    core::mem::forget(s.batch(plan()?, 0)?);
    assert!(matches!(s.batch(plan()?, 0), Err(Error::Busy)));
    s.close()?;
    let mut s = session();
    drop(complete(&mut s)?);
    assert_eq!(s.state(), State::Quarantined);
    let mut s = session();
    let mut batch = s.batch(plan()?, 0)?;
    drop(batch.item()?);
    assert!(matches!(batch.item(), Err(Error::Quarantined)));
    assert!(matches!(batch.seal(), Err(Error::Quarantined)));
    s.close()?;
    Ok(())
}
#[test]
fn invalid_bits_failed_exports_and_unwind_preserve_output() -> Result<(), Error> {
    let mut s = session();
    let mut batch = s.batch(plan()?, 1)?;
    assert_eq!(batch.item()?.finish_bits(&[1], 1), Err(Error::Bounds));
    assert!(matches!(batch.seal(), Err(Error::Quarantined)));
    for unwind in [false, true] {
        let mut s = session();
        let result = complete(&mut s)?;
        result.0.session.0.transport.0.fail = !unwind;
        result.0.session.0.transport.0.panic = unwind;
        let mut out = [0xa5; 512];
        let returned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            result.declassify(&mut out, PublicDeclassification::acknowledge())
        }));
        if unwind {
            assert!(returned.is_err());
        } else {
            assert!(matches!(returned, Ok(Err(Error::Protocol))));
        }
        assert_eq!(out, [0xa5; 512]);
        assert_eq!(s.state(), State::Quarantined);
    }
    Ok(())
}
