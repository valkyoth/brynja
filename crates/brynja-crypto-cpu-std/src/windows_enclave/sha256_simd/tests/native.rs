use super::*;
fn reference(algorithm: Algorithm, input: &[u8], last: u8) -> Result<std::vec::Vec<u8>, Error> {
    use brynja_hash_sha2::*;
    let bits = BitString::new(input, last).map_err(|_| Error::Bounds)?;
    Ok(match algorithm.wire() {
        1 => sha224_bits(bits)
            .map_err(|_| Error::Protocol)?
            .as_bytes()
            .to_vec(),
        2 => sha256_bits(bits)
            .map_err(|_| Error::Protocol)?
            .as_bytes()
            .to_vec(),
        _ => return Err(Error::Bounds),
    })
}
fn case(
    s: &mut Session,
    algorithms: [Algorithm; 8],
    lengths: [usize; 8],
    last: [u8; 8],
) -> Result<(), Error> {
    let mut data = lengths.map(|length| std::vec![0x80; length]);
    let mut expected = [0; 256];
    for (lane, (((message, algorithm), last), output)) in data
        .iter_mut()
        .zip(algorithms)
        .zip(last)
        .zip(expected.chunks_exact_mut(32))
        .enumerate()
    {
        message.fill(u8::try_from(lane).map_err(|_| Error::Bounds)?);
        *message.last_mut().ok_or(Error::Bounds)? = 0x80;
        let digest = reference(algorithm, message, last)?;
        output
            .get_mut(..digest.len())
            .ok_or(Error::Bounds)?
            .copy_from_slice(&digest);
    }
    let mut input = empty();
    for ((slot, bytes), last) in input.iter_mut().zip(&data).zip(last) {
        *slot = Input::bits(bytes, last);
    }
    let retained = s.digest(Plan::new(algorithms)?, input, 1000)?;
    let mut output = [0xa5; 256];
    retained.declassify(&mut output, PublicDeclassification::acknowledge())?;
    assert_eq!(output, expected);
    assert_eq!(s.state(), State::Ready);
    Ok(())
}
#[test]
#[ignore = "requires a reviewed development-signed version-21 image on native Windows VBS"]
fn development_sha256_simd_host_campaign() -> Result<(), Box<dyn std::error::Error>> {
    let location = std::path::PathBuf::from(std::env::var("BRYNJA_ENCLAVE_SHA256_SIMD_IMAGE")?);
    let expected = std::env::var("BRYNJA_ENCLAVE_SHA256_SIMD_SHA256")?;
    assert_eq!(expected.len(), 64);
    let mut digest = [0; 32];
    for (out, pair) in digest.iter_mut().zip(expected.as_bytes().chunks_exact(2)) {
        *out = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    let mut family = [0; 16];
    family[..4].copy_from_slice(b"BRYN");
    let mut image = [0; 16];
    image[..4].copy_from_slice(b"PROB");
    let policy = Box::leak(Box::new(ImagePolicy::reviewed_sha256(
        digest,
        family,
        image,
        1,
        1,
        [0, 0],
    )));
    assert_eq!(
        Session::open_avx2(&location, policy).err(),
        Some(Error::Signature)
    );
    let mut wrong = ImagePolicy::reviewed_sha256([0; 32], family, image, 1, 1, [0, 0]);
    assert!(Transport::development(&location, &wrong).is_err());
    let other = std::path::PathBuf::from(std::env::var("BRYNJA_ENCLAVE_OTHER_SIMD_IMAGE")?);
    let other_hash = std::env::var("BRYNJA_ENCLAVE_OTHER_SIMD_SHA256")?;
    assert_eq!(other_hash.len(), 64);
    let mut other_digest = [0; 32];
    for (out, pair) in other_digest
        .iter_mut()
        .zip(other_hash.as_bytes().chunks_exact(2))
    {
        *out = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    // Correct hash/PE identity, but a different admitted SIMD protocol must fail.
    let other_policy = ImagePolicy::reviewed_sha256(other_digest, family, image, 1, 1, [0, 0]);
    assert!(Transport::development(&other, &other_policy).is_err());
    wrong.digest = policy.digest;
    wrong.family = [0; 16];
    assert!(Transport::development(&location, &wrong).is_err());
    let open = || Transport::development(&location, policy).map(|t| Session(Owner::new(t)));
    let mut s = open()?;
    let mut batches = 0_usize;
    for algorithm in [Algorithm::SHA224, Algorithm::SHA256] {
        for length in [64, 65, 119, 120, 127, 128, 129, 255, 1023, 1024] {
            for last in 1..=8 {
                if length == 64 && last != 8 {
                    continue;
                }
                case(&mut s, [algorithm; 8], [length; 8], [last; 8])?;
                batches = batches.checked_add(1).ok_or(Error::Bounds)?;
            }
        }
    }
    for mut mask in 0..=255_u8 {
        let algorithms = core::array::from_fn(|_| {
            let algorithm = if mask & 1 == 0 {
                Algorithm::SHA224
            } else {
                Algorithm::SHA256
            };
            mask >>= 1;
            algorithm
        });
        case(
            &mut s,
            algorithms,
            [65, 119, 120, 127, 128, 129, 1023, 1024],
            [1, 2, 3, 4, 5, 6, 7, 8],
        )?;
        batches = batches.checked_add(1).ok_or(Error::Bounds)?;
    }
    s.digest(plan()?, input(&[0; 64]), 100)?.cancel()?;
    case(&mut s, [Algorithm::SHA224; 8], [64; 8], [8; 8])?;
    batches = batches.checked_add(1).ok_or(Error::Bounds)?;
    core::mem::forget(s.digest(plan()?, input(&[0; 64]), 100)?);
    assert!(matches!(
        s.digest(plan()?, input(&[0; 64]), 100),
        Err(Error::Busy)
    ));
    s.close()?;
    assert_eq!(s.state(), State::Closed);
    let mut s = open()?;
    drop(s.digest(plan()?, input(&[0; 64]), 100)?);
    assert_eq!(s.state(), State::Quarantined);
    s.close()?;
    for kind in [0, 1, 2] {
        let mut s = open()?;
        if kind == 0 {
            assert!(s.digest(plan()?, input(&[0; 64]), 0).is_err());
        } else if kind == 1 {
            let data = [0xff; 65];
            assert!(
                s.digest(
                    plan()?,
                    core::array::from_fn(|_| Input::bits(&data, 7)),
                    100
                )
                .is_err()
            );
        } else {
            let mut retained = s.digest(plan()?, input(&[0; 64]), 100)?;
            retained.0.plan = Plan::new([Algorithm::SHA224; 8])?;
            let mut output = [0xa5; 256];
            assert!(
                retained
                    .declassify(&mut output, PublicDeclassification::acknowledge())
                    .is_err()
            );
            assert_eq!(output, [0xa5; 256]);
        }
        assert_eq!(s.state(), State::Quarantined);
        assert!(matches!(
            s.digest(plan()?, input(&[0; 64]), 100),
            Err(Error::Quarantined)
        ));
        // Lost completion is terminal: retain uncertain mappings until the test
        // process exits, rather than claiming verified enclave cleanup.
        assert_eq!(s.close(), Err(Error::Release));
    }
    assert_eq!(batches, 403);
    println!(
        "WINDOWS_ENCLAVE_SHA256_SIMD_HOST: batches={batches}; digests=3224; trust/cancel/forget/quarantine/transactional=PASS; development_only=true"
    );
    Ok(())
}
