use super::*;
fn empty() -> Result<Bits<'static>, Error> {
    Bits::new(&[], 0).map_err(|_| Error::Bounds)
}
fn reader(output: Finalized<'_>) -> Result<Reader<'_>, Error> {
    match output {
        Finalized::Reader(r) => Ok(r),
        _ => Err(Error::Protocol),
    }
}
fn reference(
    algorithm: Algorithm,
    input: Bits<'_>,
    name: Bits<'_>,
    custom: Bits<'_>,
) -> Result<std::vec::Vec<u8>, Error> {
    use brynja_hash_sha3::*;
    let mut output = std::vec![0;algorithm.width().unwrap_or(201)];
    match algorithm {
        Algorithm::Sha3_224 => output.copy_from_slice(
            sha3_224_bits(input)
                .map_err(|_| Error::Protocol)?
                .as_bytes(),
        ),
        Algorithm::Sha3_256 => output.copy_from_slice(
            sha3_256_bits(input)
                .map_err(|_| Error::Protocol)?
                .as_bytes(),
        ),
        Algorithm::Sha3_384 => output.copy_from_slice(
            sha3_384_bits(input)
                .map_err(|_| Error::Protocol)?
                .as_bytes(),
        ),
        Algorithm::Sha3_512 => output.copy_from_slice(
            sha3_512_bits(input)
                .map_err(|_| Error::Protocol)?
                .as_bytes(),
        ),
        Algorithm::Shake128 | Algorithm::Cshake128 => cshake128_bits(
            input,
            name,
            custom,
            Fips202Output::new(&mut output, 3).map_err(|_| Error::Bounds)?,
        )
        .map_err(|_| Error::Protocol)?,
        Algorithm::Shake256 | Algorithm::Cshake256 => cshake256_bits(
            input,
            name,
            custom,
            Fips202Output::new(&mut output, 3).map_err(|_| Error::Bounds)?,
        )
        .map_err(|_| Error::Protocol)?,
    }
    Ok(output)
}
fn export(output: Finalized<'_>, expected: &[u8]) -> Result<(), Error> {
    match output {
        Finalized::Digest(result) => {
            let mut actual = std::vec![0xa5;expected.len()];
            assert!(
                result
                    .declassify(&mut actual, PublicDeclassification::acknowledge())?
                    .is_none()
            );
            assert_eq!(actual, expected);
        }
        Finalized::Reader(r) => {
            let r = r
                .retain(0, 0, false)?
                .declassify(&mut [], PublicDeclassification::acknowledge())?
                .ok_or(Error::Protocol)?;
            let mut actual = [0xa5; 201];
            let r = r
                .retain(97, 8, false)?
                .declassify(
                    actual.get_mut(..97).ok_or(Error::Bounds)?,
                    PublicDeclassification::acknowledge(),
                )?
                .ok_or(Error::Protocol)?;
            assert!(
                r.retain(104, 3, true)?
                    .declassify(
                        actual.get_mut(97..).ok_or(Error::Bounds)?,
                        PublicDeclassification::acknowledge()
                    )?
                    .is_none()
            );
            assert_eq!(actual, expected);
        }
    }
    Ok(())
}
#[test]
#[ignore = "requires reviewed development-signed version-seven worker on native Windows VBS"]
fn development_sha3_streaming_campaign() -> Result<(), Box<dyn std::error::Error>> {
    let (location, policy) = image("BRYNJA_ENCLAVE_SHA3")?;
    campaign(Transport::development(&location, &policy)?, "SCALAR")
}
pub(super) fn image(
    prefix: &str,
) -> Result<(std::path::PathBuf, ImagePolicy), Box<dyn std::error::Error>> {
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
    let policy = ImagePolicy::reviewed_sha256(digest, family, image, 1, 1, [0, 0]);
    Ok((location, policy))
}
pub(super) fn campaign(
    transport: Transport,
    route: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session(Owner {
        transport,
        state: State::Ready,
        sequence: 0,
        thread_bound: PhantomData,
    });
    let mut cases = 0_usize;
    for algorithm in [
        Algorithm::Sha3_224,
        Algorithm::Sha3_256,
        Algorithm::Sha3_384,
        Algorithm::Sha3_512,
        Algorithm::Shake128,
        Algorithm::Shake256,
        Algorithm::Cshake128,
        Algorithm::Cshake256,
    ] {
        for length in [
            0, 1, 71, 72, 73, 135, 136, 137, 143, 144, 145, 167, 168, 169, 1024, 2057,
        ] {
            for last in 1..=8 {
                let mut message = std::vec![0x37;length];
                let last = if length == 0 { 0 } else { last };
                if let Some(tail) = message.last_mut() {
                    *tail &= u8::MAX
                        .checked_shr(u32::from(8_u8.checked_sub(last).ok_or(Error::Bounds)?))
                        .ok_or(Error::Bounds)?;
                }
                let input = Bits::new(&message, last).map_err(|_| Error::Bounds)?;
                let n = [5];
                let s = [2];
                let (name, custom) =
                    if matches!(algorithm, Algorithm::Cshake128 | Algorithm::Cshake256) {
                        (
                            Bits::new(&n, 3).map_err(|_| Error::Bounds)?,
                            Bits::new(&s, 2).map_err(|_| Error::Bounds)?,
                        )
                    } else {
                        (empty()?, empty()?)
                    };
                let expected = reference(algorithm, input, name, custom)?;
                let mut stream = if matches!(algorithm, Algorithm::Cshake128 | Algorithm::Cshake256)
                {
                    session.customized(algorithm, name, custom)?
                } else {
                    session.stream(algorithm)?
                };
                stream.update(&[])?;
                export(stream.finalize_bits(input)?, &expected)?;
                assert_eq!(session.state(), State::Ready);
                cases = cases.checked_add(1).ok_or(Error::Bounds)?;
            }
        }
    }
    for algorithm in [Algorithm::Cshake128, Algorithm::Cshake256] {
        let n = std::vec![0x35;4097];
        let s = std::vec![0x96;8193];
        let name = Bits::new(&n, 8).map_err(|_| Error::Bounds)?;
        let custom = Bits::new(&s, 8).map_err(|_| Error::Bounds)?;
        let input = Bits::new(b"abc", 8).map_err(|_| Error::Bounds)?;
        export(
            session
                .customized(algorithm, name, custom)?
                .finalize_bits(input)?,
            &reference(algorithm, input, name, custom)?,
        )?;
        let retained = reader(session.stream(Algorithm::Shake128)?.finalize_bits(input)?)?
            .retain(1, 3, true)?;
        let mut source = [0; 1];
        brynja_hash_sha3::shake128_bits(
            input,
            brynja_hash_sha3::Fips202Output::new(&mut source, 3).map_err(|_| Error::Bounds)?,
        )
        .map_err(|_| Error::Protocol)?;
        export(
            retained.rehash_customized(algorithm, name, custom)?,
            &reference(
                algorithm,
                Bits::new(&source, 3).map_err(|_| Error::Bounds)?,
                name,
                custom,
            )?,
        )?;
        cases = cases.checked_add(2).ok_or(Error::Bounds)?;
    }
    session.stream(Algorithm::Sha3_256)?.cancel()?;
    reader(session.stream(Algorithm::Shake256)?.finalize()?)?.cancel()?;
    reader(session.stream(Algorithm::Shake256)?.finalize()?)?
        .retain(1, 8, false)?
        .cancel()?;
    assert_eq!(session.state(), State::Ready);
    drop(session.stream(Algorithm::Sha3_256)?.finalize()?);
    assert_eq!(session.state(), State::Quarantined);
    session.close()?;
    println!(
        "WINDOWS_ENCLAVE_SHA3: PASS; cases={cases}; route={route}; streamed_setup=PASS; retained_rehash=PASS; abandonment=PASS; development_only=true"
    );
    Ok(())
}
