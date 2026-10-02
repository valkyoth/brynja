use super::*;
fn reference(algorithm: Algorithm, input: &[u8], last: u8) -> Result<std::vec::Vec<u8>, Error> {
    use brynja_hash_sha2::*;
    let bits = BitString::new(input, last).map_err(|_| Error::Bounds)?;
    Ok(match algorithm.wire() {
        3 => sha384_bits(bits)
            .map_err(|_| Error::Protocol)?
            .as_bytes()
            .to_vec(),
        4 => sha512_bits(bits)
            .map_err(|_| Error::Protocol)?
            .as_bytes()
            .to_vec(),
        5 => sha512_224_bits(bits)
            .map_err(|_| Error::Protocol)?
            .as_bytes()
            .to_vec(),
        6 => sha512_256_bits(bits)
            .map_err(|_| Error::Protocol)?
            .as_bytes()
            .to_vec(),
        n => sha512_t_bits(
            Sha512TBits::new(u16::try_from(n & 0xfff).map_err(|_| Error::Bounds)?)
                .map_err(|_| Error::Bounds)?,
            bits,
        )
        .map_err(|_| Error::Protocol)?
        .as_bytes()
        .to_vec(),
    })
}
fn case(
    s: &mut Session,
    algorithms: [Algorithm; 4],
    lengths: [usize; 4],
    last: [u8; 4],
) -> Result<(), Error> {
    let mut data = lengths.map(|length| std::vec![0x80; length]);
    let mut expected = [0; 256];
    for (((message, algorithm), last), output) in data
        .iter_mut()
        .zip(algorithms)
        .zip(last)
        .zip(expected.chunks_exact_mut(64))
    {
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
#[ignore = "requires a reviewed development-signed version-20 image on native Windows VBS"]
fn development_sha512_simd_host_campaign() -> Result<(), Box<dyn std::error::Error>> {
    let location = std::path::PathBuf::from(std::env::var("BRYNJA_ENCLAVE_SHA512_SIMD_IMAGE")?);
    let expected = std::env::var("BRYNJA_ENCLAVE_SHA512_SIMD_SHA256")?;
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
    wrong.digest = policy.digest;
    wrong.family = [0; 16];
    assert!(Transport::development(&location, &wrong).is_err());
    let open = || Transport::development(&location, policy).map(|t| Session(Owner::new(t)));
    let mut s = open()?;
    let named = [
        Algorithm::SHA384,
        Algorithm::SHA512,
        Algorithm::SHA512_224,
        Algorithm::SHA512_256,
    ];
    let mut batches = 0_usize;
    for algorithm in named {
        for length in [128, 129, 239, 240, 255, 256, 511, 1024] {
            case(&mut s, [algorithm; 4], [length; 4], [8; 4])?;
            batches = batches.checked_add(1).ok_or(Error::Bounds)?;
        }
    }
    for bits in 1..512 {
        if bits == 384 {
            continue;
        }
        case(&mut s, [Algorithm::sha512_t(bits)?; 4], [129; 4], [7; 4])?;
        batches = batches.checked_add(1).ok_or(Error::Bounds)?;
    }
    for last in 1..=8 {
        case(&mut s, named, [129, 239, 255, 1024], [last; 4])?;
        case(
            &mut s,
            [
                Algorithm::sha512_t(1)?,
                Algorithm::SHA512,
                Algorithm::sha512_t(511)?,
                Algorithm::SHA512_224,
            ],
            [1024, 511, 256, 240],
            [last; 4],
        )?;
        batches = batches.checked_add(2).ok_or(Error::Bounds)?;
    }
    s.digest(plan()?, input(&[0; 128]), 100)?.cancel()?;
    case(&mut s, named, [128; 4], [8; 4])?;
    batches = batches.checked_add(1).ok_or(Error::Bounds)?;
    core::mem::forget(s.digest(plan()?, input(&[0; 128]), 100)?);
    assert!(matches!(
        s.digest(plan()?, input(&[0; 128]), 100),
        Err(Error::Busy)
    ));
    s.close()?;
    assert_eq!(s.state(), State::Closed);
    let mut s = open()?;
    drop(s.digest(plan()?, input(&[0; 128]), 100)?);
    assert_eq!(s.state(), State::Quarantined);
    s.close()?;
    for kind in [0, 1, 2] {
        let mut s = open()?;
        if kind == 0 {
            assert!(s.digest(plan()?, input(&[0; 128]), 0).is_err());
        } else if kind == 1 {
            let data = [0xff; 129];
            assert!(
                s.digest(
                    plan()?,
                    core::array::from_fn(|_| Input::bits(&data, 7)),
                    100
                )
                .is_err()
            );
        } else {
            let mut retained = s.digest(plan()?, input(&[0; 128]), 100)?;
            retained.0.plan = Plan::new([Algorithm::SHA384; 4])?;
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
            s.digest(plan()?, input(&[0; 128]), 100),
            Err(Error::Quarantined)
        ));
        // Lost completion is terminal: retain uncertain mappings until the test
        // process exits, rather than claiming verified enclave cleanup.
        assert_eq!(s.close(), Err(Error::Release));
    }
    assert_eq!(batches, 559);
    println!(
        "WINDOWS_ENCLAVE_SHA512_SIMD_HOST: batches={batches}; digests=2236; trust/cancel/forget/quarantine/transactional=PASS; development_only=true"
    );
    Ok(())
}
