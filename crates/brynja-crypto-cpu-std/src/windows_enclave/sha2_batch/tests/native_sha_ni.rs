use super::*;

fn image(prefix: &str) -> Result<(std::path::PathBuf, ImagePolicy), Box<dyn std::error::Error>> {
    let location = std::path::PathBuf::from(std::env::var(format!("{prefix}_IMAGE"))?);
    let expected = std::env::var(format!("{prefix}_SHA256"))?;
    if expected.len() != 64 {
        return Err("expected exact image hash".into());
    }
    let mut digest = [0; 32];
    for (out, pair) in digest.iter_mut().zip(expected.as_bytes().chunks_exact(2)) {
        *out = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    let mut family = [0; 16];
    let mut image = [0; 16];
    family
        .get_mut(..4)
        .ok_or(Error::Bounds)?
        .copy_from_slice(b"BRYN");
    image
        .get_mut(..4)
        .ok_or(Error::Bounds)?
        .copy_from_slice(b"PROB");
    Ok((
        location,
        ImagePolicy::reviewed_sha256(digest, family, image, 1, 1, [0, 0]),
    ))
}
fn session(transport: Transport) -> Session {
    Session(Owner {
        transport,
        state: State::Ready,
        sequence: 0,
        thread_bound: PhantomData,
    })
}
#[test]
#[ignore = "requires reviewed scalar and SHA-NI development-signed images on native Windows VBS"]
fn development_sha_ni_batch_host_campaign() -> Result<(), Box<dyn std::error::Error>> {
    let (location, policy) = image("BRYNJA_ENCLAVE_SHA2_BATCH_SHA_NI")?;
    let policy = Box::leak(Box::new(policy));
    assert!(matches!(
        Session::open_sha_ni(&location, policy),
        Err(Error::Signature)
    ));
    assert!(matches!(
        Session::open(&location, policy),
        Err(Error::Signature)
    ));
    let (scalar_location, scalar_policy) = image("BRYNJA_ENCLAVE_SHA2_BATCH")?;
    assert!(Transport::development_sha_ni(&scalar_location, &scalar_policy).is_err());
    let mut wrong = ImagePolicy::reviewed_sha256([1; 32], [1; 16], [2; 16], 1, 1, [0, 0]);
    assert!(Transport::development_sha_ni(&location, &wrong).is_err());
    wrong.digest = policy.digest;
    assert!(Transport::development_sha_ni(&location, &wrong).is_err());
    let mut s = session(Transport::development_sha_ni(&location, policy)?);
    let algorithms = [
        Algorithm::SHA224,
        Algorithm::SHA256,
        Algorithm::SHA224,
        Algorithm::SHA256,
        Algorithm::SHA224,
        Algorithm::SHA256,
        Algorithm::SHA224,
        Algorithm::SHA256,
    ];
    let mut batches = 0_usize;
    let mut digests = 0_usize;
    for length in [0, 1, 55, 56, 63, 64, 111, 112, 127, 128, 1024, 2049] {
        for last in [1, 7, 8] {
            digests = digests
                .checked_add(native::case(
                    &mut s,
                    Plan::new(algorithms.map(Some))?,
                    length,
                    last,
                )?)
                .ok_or(Error::Bounds)?;
            batches = batches.checked_add(1).ok_or(Error::Bounds)?;
        }
    }
    for mask in 1_u16..=255 {
        let plan = Plan::new(core::array::from_fn(|i| {
            if mask & (1 << i) != 0 {
                algorithms.get(i).copied()
            } else {
                None
            }
        }))?;
        digests = digests
            .checked_add(native::case(&mut s, plan, 3, 7)?)
            .ok_or(Error::Bounds)?;
        batches = batches.checked_add(1).ok_or(Error::Bounds)?;
    }
    let plan = Plan::new([Some(Algorithm::SHA256); 8])?;
    s.batch(plan, 0)?.cancel()?;
    let mut batch = s.batch(plan, 3)?;
    batch.item()?.finish_bits(b"abc", 8)?;
    core::mem::forget(batch.item()?);
    batch.cancel()?;
    assert_eq!(s.state(), State::Ready);
    let mut batch = s.batch(plan, 0)?;
    core::mem::forget(batch.item()?);
    assert!(batch.seal().is_err());
    assert_eq!(s.state(), State::Quarantined);
    s.close()?;
    assert_eq!(s.state(), State::Closed);
    // Valid wide plans never fall back; host rejection still permits confirmed destruction.
    for wide in [
        Algorithm::SHA384,
        Algorithm::SHA512,
        Algorithm::SHA512_224,
        Algorithm::SHA512_256,
        Algorithm::sha512_t(1)?,
        Algorithm::sha512_t(511)?,
    ] {
        let mut s = session(Transport::development_sha_ni(&location, policy)?);
        assert!(matches!(
            s.batch(Plan::new([Some(wide); 8])?, 0),
            Err(Error::Bounds)
        ));
        assert_eq!(s.state(), State::Quarantined);
        assert!(matches!(s.batch(plan, 0), Err(Error::Quarantined)));
        s.close()?;
    }
    let mut s = session(Transport::development_sha_ni(&location, policy)?);
    let mut slots = [None; 8];
    *slots.get_mut(0).ok_or(Error::Bounds)? = Some(Algorithm::SHA256);
    let mut batch = s.batch(Plan::new(slots)?, 3)?;
    batch.item()?.finish_bits(b"abc", 8)?;
    let mut retained = batch.seal()?;
    *slots.get_mut(0).ok_or(Error::Bounds)? = Some(Algorithm::SHA224);
    retained.0.plan = Plan::new(slots)?;
    let mut untouched = [0xa5; 512];
    assert!(matches!(
        retained.declassify(&mut untouched, PublicDeclassification::acknowledge()),
        Err(Error::Protocol)
    ));
    assert_eq!(untouched, [0xa5; 512]);
    assert_eq!(s.state(), State::Quarantined);
    // Backend rejection makes cleanup uncertain; child-process exit contains
    // deliberately retained resources, not a claimed clean release.
    assert_eq!(s.close(), Err(Error::Release));
    println!(
        "WINDOWS_ENCLAVE_SHA2_BATCH_SHA_NI_HOST: batches={batches}; digests={digests}; trust/wide/transactional_rejections=PASS; development_only=true"
    );
    Ok(())
}
