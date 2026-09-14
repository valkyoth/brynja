use super::*;

#[test]
fn portable_never_requires_cpu_and_selection_is_explicit() -> Result<(), Error> {
    let owner = Authority::new(Mode::Portable)?;
    assert_eq!(owner.kernel()?, None);
    assert!(owner.executor(0).is_err());
    assert!(owner.executor(1).is_ok());
    owner.quarantine();
    assert_eq!(owner.kernel()?, None);
    let preferred = Authority::new(Mode::Prefer)?;
    match preferred.kernel()? {
        None => assert!(matches!(
            Authority::new(Mode::Require),
            Err(Error::Unavailable)
        )),
        Some(_) => {
            assert!(Authority::new(Mode::Require).is_ok());
            preferred.quarantine();
            assert!(preferred.kernel().is_err());
            assert!(preferred.executor(1).is_err());
        }
    }
    Ok(())
}
