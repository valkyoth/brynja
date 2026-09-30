use super::*;

#[test]
#[ignore = "requires an explicitly reviewed development-signed SHA-2 worker on native Windows VBS"]
fn development_sha2_streaming_campaign() -> Result<(), Box<dyn std::error::Error>> {
    let location = std::path::PathBuf::from(std::env::var("BRYNJA_ENCLAVE_SHA2_IMAGE")?);
    let expected = std::env::var("BRYNJA_ENCLAVE_SHA2_SHA256")?;
    let mut digest = [0; 32];
    if expected.len() != 64 {
        return Err("expected complete image hash".into());
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
    let policy = ImagePolicy::reviewed_sha256(digest, family, image, 1, 1, [0, 0]);
    // This constructor is test-only. Production never accepts a failed trust check.
    let transport = Transport::development(&location, &policy)?;
    let mut session = Session(Owner {
        transport,
        state: State::Ready,
        sequence: 0,
        thread_bound: PhantomData,
    });
    let mut cases = 0_usize;
    for (algorithm, identity) in [
        Algorithm::SHA224,
        Algorithm::SHA256,
        Algorithm::SHA384,
        Algorithm::SHA512,
        Algorithm::SHA512_224,
        Algorithm::SHA512_256,
    ]
    .into_iter()
    .zip(1..=6)
    {
        for length in [0, 1, 55, 56, 63, 64, 111, 112, 127, 128, 1024, 2057] {
            let message = std::vec![0x37;length];
            let expected: std::vec::Vec<u8> = match identity {
                1 => brynja_hash_sha2::sha224(&message)
                    .map_err(|_| Error::Protocol)?
                    .as_bytes()
                    .to_vec(),
                2 => brynja_hash_sha2::sha256(&message)
                    .map_err(|_| Error::Protocol)?
                    .as_bytes()
                    .to_vec(),
                3 => brynja_hash_sha2::sha384(&message)
                    .map_err(|_| Error::Protocol)?
                    .as_bytes()
                    .to_vec(),
                4 => brynja_hash_sha2::sha512(&message)
                    .map_err(|_| Error::Protocol)?
                    .as_bytes()
                    .to_vec(),
                5 => brynja_hash_sha2::sha512_224(&message)
                    .map_err(|_| Error::Protocol)?
                    .as_bytes()
                    .to_vec(),
                _ => brynja_hash_sha2::sha512_256(&message)
                    .map_err(|_| Error::Protocol)?
                    .as_bytes()
                    .to_vec(),
            };
            let mut stream = session.stream(algorithm)?;
            for chunk in message.chunks(113) {
                stream.update(chunk)?;
            }
            stream.update(&[])?;
            let result = stream.finalize()?;
            let mut public = std::vec![0xa5;algorithm.output_bytes()];
            result.declassify(&mut public, PublicDeclassification::acknowledge())?;
            assert_eq!(public, expected);
            assert_eq!(session.state(), State::Ready);
            cases = cases.checked_add(1).ok_or(Error::Bounds)?;
        }
    }
    // General /224 is parameter-specific but mathematically matches named /224.
    for bits in (1..512).filter(|&t| t != 384) {
        let algorithm = Algorithm::sha512_t(bits)?;
        let mut stream = session.stream(algorithm)?;
        stream.update(b"abc")?;
        let result = stream.finalize()?;
        assert_eq!(result.algorithm(), algorithm);
        let mut public = std::vec![0;algorithm.output_bytes()];
        result.declassify(&mut public, PublicDeclassification::acknowledge())?;
        let parameter = brynja_hash_sha2::Sha512TBits::new(bits).map_err(|_| Error::Bounds)?;
        let expected =
            brynja_hash_sha2::sha512_t(parameter, b"abc").map_err(|_| Error::Protocol)?;
        assert_eq!(public, expected.as_bytes());
        if bits % 8 != 0 {
            let mask = 0xff_u8
                .checked_shr(u32::from(bits % 8))
                .ok_or(Error::Bounds)?;
            assert_eq!(public.last().ok_or(Error::Bounds)? & mask, 0);
        }
        cases = cases.checked_add(1).ok_or(Error::Bounds)?;
    }
    for last in 1..=8 {
        let tail = [0x80];
        let bits = brynja_hash_sha2::BitString::new(&tail, last).map_err(|_| Error::Bounds)?;
        for algorithm in [
            Algorithm::SHA224,
            Algorithm::SHA256,
            Algorithm::SHA384,
            Algorithm::SHA512,
            Algorithm::SHA512_224,
            Algorithm::SHA512_256,
        ] {
            let expected = match algorithm {
                Algorithm::SHA224 => brynja_hash_sha2::sha224_bits(bits)
                    .map_err(|_| Error::Protocol)?
                    .as_bytes()
                    .to_vec(),
                Algorithm::SHA256 => brynja_hash_sha2::sha256_bits(bits)
                    .map_err(|_| Error::Protocol)?
                    .as_bytes()
                    .to_vec(),
                Algorithm::SHA384 => brynja_hash_sha2::sha384_bits(bits)
                    .map_err(|_| Error::Protocol)?
                    .as_bytes()
                    .to_vec(),
                Algorithm::SHA512 => brynja_hash_sha2::sha512_bits(bits)
                    .map_err(|_| Error::Protocol)?
                    .as_bytes()
                    .to_vec(),
                Algorithm::SHA512_224 => brynja_hash_sha2::sha512_224_bits(bits)
                    .map_err(|_| Error::Protocol)?
                    .as_bytes()
                    .to_vec(),
                _ => brynja_hash_sha2::sha512_256_bits(bits)
                    .map_err(|_| Error::Protocol)?
                    .as_bytes()
                    .to_vec(),
            };
            let result = session.stream(algorithm)?.finalize_bits(&tail, last)?;
            let mut public = std::vec![0;algorithm.output_bytes()];
            result.declassify(&mut public, PublicDeclassification::acknowledge())?;
            assert_eq!(public, expected);
            cases = cases.checked_add(1).ok_or(Error::Bounds)?;
        }
    }
    let mut stream = session.stream(Algorithm::SHA256)?;
    stream.update(&std::vec![b'a';1_000_000])?;
    let mut million = [0; 32];
    stream
        .finalize()?
        .declassify(&mut million, PublicDeclassification::acknowledge())?;
    assert_eq!(
        million,
        [
            0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92, 0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7,
            0x3e, 0x67, 0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e, 0x04, 0x6d, 0x39, 0xcc,
            0xc7, 0x11, 0x2c, 0xd0
        ]
    );
    cases = cases.checked_add(1).ok_or(Error::Bounds)?;
    let mut stream = session.stream(Algorithm::SHA256)?;
    stream.update(b"abc")?;
    let result = stream.finalize()?.rehash(Algorithm::SHA512)?;
    let mut public = [0; 64];
    result.declassify(&mut public, PublicDeclassification::acknowledge())?;
    assert_eq!(
        public,
        brynja_hash_sha2::sha512(
            brynja_hash_sha2::sha256(b"abc")
                .map_err(|_| Error::Protocol)?
                .as_bytes()
        )
        .map_err(|_| Error::Protocol)?
        .as_bytes()
        .as_slice()
    );
    session.stream(Algorithm::SHA256)?.cancel()?;
    session.stream(Algorithm::SHA512)?.finalize()?.cancel()?;
    drop(session.stream(Algorithm::SHA256)?.finalize()?);
    assert_eq!(session.state(), State::Quarantined);
    session.close()?;
    assert_eq!(session.state(), State::Closed);
    println!(
        "WINDOWS_ENCLAVE_SHA2: PASS; cases={cases}; retained_rehash=PASS; abandonment=PASS; development_only=true"
    );
    Ok(())
}
