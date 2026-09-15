use super::*;
#[test]
fn portable_never_acquires_authority() -> Result<(), Error> {
    let owner = Authority::new(Mode::Portable)?;
    assert_eq!(owner.kernel()?, None);
    owner.quarantine();
    let executor = owner.executor(1)?;
    let bits = brynja_hash_sha3::Fips202BitString::new(b"abc", 8)
        .map_err(|_| Error::Execution(brynja_hash_sha3::batch::Error::InvalidInput))?;
    let input = Input::new(Algorithm::Sha3_256, bits, 256).map_err(Error::Execution)?;
    let mut output = [0; 32];
    let mut cancel = || false;
    let report = executor
        .digest(
            PublicData::new(&[input]),
            &mut [&mut output],
            &mut Workspace::new(),
            &mut [0; 32],
            &mut Control::new(2, &mut cancel),
        )
        .map_err(Error::Execution)?;
    assert_eq!(report.kernel, None);
    assert_eq!(report.scalar_permutations, 1);
    assert_eq!(
        output.as_slice(),
        brynja_hash_sha3::sha3_256(b"abc")
            .map_err(|_| Error::Execution(brynja_hash_sha3::batch::Error::Invariant))?
            .as_bytes()
    );
    Ok(())
}
#[test]
fn selection_and_revocation_never_silently_fallback() -> Result<(), Error> {
    let preferred = Authority::new(Mode::Prefer)?;
    if preferred.kernel()?.is_some() {
        preferred.quarantine();
        assert!(preferred.kernel().is_err());
        assert!(preferred.executor(1).is_err());
    } else {
        assert!(matches!(
            Authority::new(Mode::Require),
            Err(Error::Unavailable)
        ));
    }
    assert!(preferred.executor(0).is_err());
    Ok(())
}
#[cfg(all(target_arch = "x86_64", not(target_feature = "avx2")))]
#[test]
fn generic_x86_has_no_hosted_lifetime_proof() {
    assert!(matches!(
        Authority::new(Mode::Require),
        Err(Error::Unavailable)
    ));
}
