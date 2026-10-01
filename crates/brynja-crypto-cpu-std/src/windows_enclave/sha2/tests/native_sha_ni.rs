use super::*;

fn image(name: &str) -> Result<(std::path::PathBuf, ImagePolicy), Box<dyn std::error::Error>> {
    let location = std::path::PathBuf::from(std::env::var(name)?);
    let expected = std::env::var(format!("{name}_SHA256"))?;
    let mut digest = [0; 32];
    if expected.len() != 64 {
        return Err("expected complete signed image hash".into());
    }
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

fn session(location: &Path, policy: &ImagePolicy) -> Result<Session, Error> {
    Ok(Session(Owner {
        transport: Transport::development_sha_ni(location, policy)?,
        state: State::Ready,
        sequence: 0,
        route: Route::ShaNi,
        thread_bound: PhantomData,
    }))
}

#[test]
#[ignore = "requires separately reviewed development-signed scalar and SHA-NI images on native Windows VBS"]
fn development_sha_ni_host_campaign() -> Result<(), Box<dyn std::error::Error>> {
    let (location, policy) = image("BRYNJA_ENCLAVE_SHA_NI_IMAGE")?;
    let policy = Box::leak(Box::new(policy));
    // Both public constructors retain mandatory production trust verification.
    assert!(matches!(
        Session::open_sha_ni(&location, policy),
        Err(Error::Signature)
    ));
    assert!(matches!(
        Session::open(&location, policy),
        Err(Error::Signature)
    ));
    let (scalar_location, scalar_policy) = image("BRYNJA_ENCLAVE_SCALAR_SHA2_IMAGE")?;
    assert!(Transport::development_sha_ni(&scalar_location, &scalar_policy).is_err());
    let mut wrong = ImagePolicy::reviewed_sha256([1; 32], [1; 16], [2; 16], 1, 1, [0, 0]);
    assert!(Transport::development_sha_ni(&location, &wrong).is_err());
    wrong.digest = policy.digest;
    assert!(Transport::development_sha_ni(&location, &wrong).is_err());
    let mut owner = session(&location, policy)?;
    let mut cases = 0_usize;
    for algorithm in [Algorithm::SHA224, Algorithm::SHA256] {
        for length in [0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 1024, 2057] {
            let message = vec![0x37; length];
            let expected = if algorithm == Algorithm::SHA224 {
                brynja_hash_sha2::sha224(&message)
                    .map_err(|_| Error::Protocol)?
                    .as_bytes()
                    .to_vec()
            } else {
                brynja_hash_sha2::sha256(&message)
                    .map_err(|_| Error::Protocol)?
                    .as_bytes()
                    .to_vec()
            };
            let mut stream = owner.stream(algorithm)?;
            for chunk in message.chunks(113) {
                stream.update(chunk)?;
            }
            stream.update(&[])?;
            let digest = stream.finalize()?;
            let mut public = vec![0xa5; algorithm.output_bytes()];
            digest.declassify(&mut public, PublicDeclassification::acknowledge())?;
            assert_eq!(public, expected);
            assert_eq!(owner.state(), State::Ready);
            cases = cases.checked_add(1).ok_or(Error::Bounds)?;
        }
        for last in 1..=8 {
            let tail = [0x80];
            let bits = brynja_hash_sha2::BitString::new(&tail, last).map_err(|_| Error::Bounds)?;
            let expected = if algorithm == Algorithm::SHA224 {
                brynja_hash_sha2::sha224_bits(bits)
                    .map_err(|_| Error::Protocol)?
                    .as_bytes()
                    .to_vec()
            } else {
                brynja_hash_sha2::sha256_bits(bits)
                    .map_err(|_| Error::Protocol)?
                    .as_bytes()
                    .to_vec()
            };
            let mut public = vec![0; algorithm.output_bytes()];
            owner
                .stream(algorithm)?
                .finalize_bits(&tail, last)?
                .declassify(&mut public, PublicDeclassification::acknowledge())?;
            assert_eq!(public, expected);
            cases = cases.checked_add(1).ok_or(Error::Bounds)?;
        }
    }
    for first in [Algorithm::SHA224, Algorithm::SHA256] {
        for second in [Algorithm::SHA224, Algorithm::SHA256] {
            let input = if first == Algorithm::SHA224 {
                brynja_hash_sha2::sha224(b"abc")
                    .map_err(|_| Error::Protocol)?
                    .as_bytes()
                    .to_vec()
            } else {
                brynja_hash_sha2::sha256(b"abc")
                    .map_err(|_| Error::Protocol)?
                    .as_bytes()
                    .to_vec()
            };
            let expected = if second == Algorithm::SHA224 {
                brynja_hash_sha2::sha224(&input)
                    .map_err(|_| Error::Protocol)?
                    .as_bytes()
                    .to_vec()
            } else {
                brynja_hash_sha2::sha256(&input)
                    .map_err(|_| Error::Protocol)?
                    .as_bytes()
                    .to_vec()
            };
            let mut public = vec![0; second.output_bytes()];
            owner
                .stream(first)?
                .finalize_bits(b"abc", 8)?
                .rehash(second)?
                .declassify(&mut public, PublicDeclassification::acknowledge())?;
            assert_eq!(public, expected);
            cases = cases.checked_add(1).ok_or(Error::Bounds)?;
        }
    }
    owner.stream(Algorithm::SHA256)?.cancel()?;
    owner.stream(Algorithm::SHA224)?.finalize()?.cancel()?;
    drop(owner.stream(Algorithm::SHA256)?.finalize()?);
    assert_eq!(owner.state(), State::Quarantined);
    owner.close()?;
    assert_eq!(owner.state(), State::Closed);
    // Host-side identity rejection must not dispatch or force scalar work.
    for algorithm in [
        Algorithm::SHA384,
        Algorithm::SHA512,
        Algorithm::SHA512_224,
        Algorithm::SHA512_256,
        Algorithm::sha512_t(224)?,
    ] {
        let mut owner = session(&location, policy)?;
        assert!(matches!(owner.stream(algorithm), Err(Error::Bounds)));
        assert_eq!(owner.state(), State::Quarantined);
        owner.close()?;
        let mut owner = session(&location, policy)?;
        assert!(matches!(
            owner
                .stream(Algorithm::SHA256)?
                .finalize()?
                .rehash(algorithm),
            Err(Error::Bounds)
        ));
        owner.close()?;
    }
    let mut owner = session(&location, policy)?;
    let mut untouched = [0xa5; 31];
    assert_eq!(
        owner
            .stream(Algorithm::SHA256)?
            .finalize()?
            .declassify(&mut untouched, PublicDeclassification::acknowledge()),
        Err(Error::Bounds)
    );
    assert_eq!(untouched, [0xa5; 31]);
    owner.close()?;
    println!(
        "WINDOWS_ENCLAVE_SHA_NI_HOST: PASS; cases={cases}; trust_rejections=PASS; image_mismatch=PASS; unsupported_identities=PASS; lifecycle=PASS; development_only=true"
    );
    Ok(())
}
