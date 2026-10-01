use super::*;

#[test]
#[ignore = "requires reviewed development-signed scalar and AVX2 images on native Windows VBS"]
fn development_avx2_parallelhash_host_campaign() -> Result<(), Box<dyn std::error::Error>> {
    let (location, policy) = native::image("BRYNJA_ENCLAVE_PARALLEL_AVX2")?;
    let policy = Box::leak(Box::new(policy));
    assert!(matches!(
        Session::open_avx2(&location, policy),
        Err(Error::Signature)
    ));
    assert!(matches!(
        Session::open(&location, policy),
        Err(Error::Signature)
    ));
    let (scalar_location, scalar_policy) = native::image("BRYNJA_ENCLAVE_PARALLEL")?;
    assert!(Transport::development_avx2(&scalar_location, &scalar_policy).is_err());
    let mut wrong = ImagePolicy::reviewed_sha256([1; 32], [1; 16], [2; 16], 1, 1, [0, 0]);
    assert!(Transport::development_avx2(&location, &wrong).is_err());
    wrong.digest = policy.digest;
    assert!(Transport::development_avx2(&location, &wrong).is_err());
    native::campaign(Transport::development_avx2(&location, policy)?, "AVX2")?;
    let mut s = Session(Owner {
        transport: Transport::development_avx2(&location, policy)?,
        state: State::Ready,
        sequence: 0,
        thread_bound: PhantomData,
    });
    let empty = Bits::new(&[], 0).map_err(|_| Error::Bounds)?;
    let mut stream = s.stream(Algorithm::ParallelHash128, 8, empty, 3)?;
    stream.update(b"abc")?;
    let mut retained = stream.finalize(empty, 32, 8)?;
    // Corrupt only public test metadata: same-size export cannot change identity.
    retained.loan.algorithm = Algorithm::ParallelHash256;
    let mut untouched = [0xa5; 32];
    assert!(matches!(
        retained.declassify(&mut untouched, PublicDeclassification::acknowledge()),
        Err(Error::Protocol)
    ));
    assert_eq!(untouched, [0xa5; 32]);
    assert_eq!(s.state(), State::Quarantined);
    // Uncertain completion retains resources until this isolated test process exits.
    assert_eq!(s.close(), Err(Error::Release));
    assert!(matches!(
        s.stream(Algorithm::ParallelHash128, 8, empty, 0),
        Err(Error::Quarantined)
    ));
    println!(
        "WINDOWS_ENCLAVE_PARALLELHASH_AVX2_HOST: PASS; trust_rejections=PASS; image_mismatch=PASS; wrong_route=PASS; transactional_output=PASS; development_only=true"
    );
    Ok(())
}
