use super::*;

#[test]
#[ignore = "requires reviewed development-signed scalar and AVX2 images on native Windows VBS"]
fn development_avx2_host_campaign() -> Result<(), Box<dyn std::error::Error>> {
    let (location, policy) = native::image("BRYNJA_ENCLAVE_TUPLEHASH_AVX2")?;
    let policy = Box::leak(Box::new(policy));
    assert!(matches!(
        Session::open_avx2(&location, policy),
        Err(Error::Signature)
    ));
    assert!(matches!(
        Session::open(&location, policy),
        Err(Error::Signature)
    ));
    let (scalar_location, scalar_policy) = native::image("BRYNJA_ENCLAVE_TUPLEHASH")?;
    assert!(Transport::development_avx2(&scalar_location, &scalar_policy).is_err());
    let mut wrong = ImagePolicy::reviewed_sha256([1; 32], [1; 16], [2; 16], 1, 1, [0, 0]);
    assert!(Transport::development_avx2(&location, &wrong).is_err());
    wrong.digest = policy.digest;
    assert!(Transport::development_avx2(&location, &wrong).is_err());
    native::campaign(Transport::development_avx2(&location, policy)?, "AVX2")?;

    let mut session = Session(Owner {
        transport: Transport::development_avx2(&location, policy)?,
        state: State::Ready,
        sequence: 0,
        thread_bound: PhantomData,
    });
    let result = session
        .stream(
            Algorithm::TupleHash128,
            Bits::new(&[], 0).map_err(|_| Error::Bounds)?,
        )?
        .finalize(32, 8)?;
    let mut untouched = [0xa5; 31];
    assert!(matches!(
        result.declassify(&mut untouched, PublicDeclassification::acknowledge()),
        Err(Error::Bounds)
    ));
    assert_eq!(untouched, [0xa5; 31]);
    assert_eq!(session.state(), State::Quarantined);
    session.close()?;
    println!(
        "WINDOWS_ENCLAVE_TUPLEHASH_AVX2_HOST: PASS; trust_rejections=PASS; image_mismatch=PASS; wrong_route=PASS; transactional_output=PASS; development_only=true"
    );
    Ok(())
}
