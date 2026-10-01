use super::*;

#[test]
#[ignore = "requires reviewed development-signed scalar and AVX2 images on native Windows VBS"]
fn development_avx2_batch_host_campaign() -> Result<(), Box<dyn std::error::Error>> {
    let (location, policy) = native::image("BRYNJA_ENCLAVE_SHA3_BATCH_AVX2")?;
    let policy = Box::leak(Box::new(policy));
    assert!(matches!(
        Session::open_avx2(&location, policy),
        Err(Error::Signature)
    ));
    assert!(matches!(
        Session::open(&location, policy),
        Err(Error::Signature)
    ));
    let (scalar_location, scalar_policy) = native::image("BRYNJA_ENCLAVE_SHA3_BATCH")?;
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
    let mut shapes = [None; 8];
    *shapes.get_mut(0).ok_or(Error::Bounds)? = Some(Output::new(Algorithm::Sha3_256, 32, 8)?);
    let mut batch = s.batch(Plan::new(shapes)?, 3)?;
    batch.item()?.finish_bits(b"abc", 8)?;
    let mut retained = batch.seal()?;
    // Test-only corruption: a valid but different plan must be rejected by the
    // enclave, not accepted merely because the fixed export width still agrees.
    *shapes.get_mut(0).ok_or(Error::Bounds)? = Some(Output::new(Algorithm::Sha3_224, 28, 8)?);
    retained.0.plan = Plan::new(shapes)?;
    let mut untouched = [0xa5; 1024];
    assert!(matches!(
        retained.declassify(&mut untouched, PublicDeclassification::acknowledge()),
        Err(Error::Protocol)
    ));
    assert_eq!(untouched, [0xa5; 1024]);
    assert_eq!(s.state(), State::Quarantined);
    // Rejected backend completion leaves release uncertain. The existing
    // contract retains enclave/file resources until process exit rather than
    // falsely report clean destruction. This native test runs in its own child.
    assert_eq!(s.close(), Err(Error::Release));
    assert_eq!(s.state(), State::Quarantined);
    assert!(matches!(
        s.batch(Plan::new(shapes)?, 0),
        Err(Error::Quarantined)
    ));
    println!(
        "WINDOWS_ENCLAVE_SHA3_BATCH_AVX2_HOST: PASS; trust_rejections=PASS; image_mismatch=PASS; wrong_route=PASS; transactional_output=PASS; development_only=true"
    );
    Ok(())
}
