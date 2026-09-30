use super::*;
fn empty() -> Result<Bits<'static>, Error> {
    bits(&[], 0)
}
fn reference(
    algorithm: Algorithm,
    key: Bits<'_>,
    custom: Bits<'_>,
    input: Bits<'_>,
    width: usize,
    last: u8,
) -> Result<std::vec::Vec<u8>, Error> {
    use brynja_mac_kmac::*;
    let mut out = std::vec![0;width];
    macro_rules! fixed {
        ($name:ident) => {{
            let _ = $name::new_bits(key, custom)
                .map_err(|_| Error::Protocol)?
                .finalize_tag_bits(input, &mut out, last)
                .map_err(|_| Error::Protocol)?;
        }};
    }
    macro_rules! xof {
        ($name:ident) => {{
            $name::new_bits(key, custom)
                .map_err(|_| Error::Protocol)?
                .finalize_bits_xof(input)
                .map_err(|_| Error::Protocol)?
                .squeeze_final_bits_public(
                    Fips202Output::new(&mut out, last).map_err(|_| Error::Bounds)?,
                    KmacPublicDeclassification::acknowledge(),
                )
                .map_err(|_| Error::Protocol)?;
        }};
    }
    match algorithm {
        Algorithm::Kmac128 => fixed!(Kmac128),
        Algorithm::Kmac256 => fixed!(Kmac256),
        Algorithm::KmacXof128 => xof!(KmacXof128),
        Algorithm::KmacXof256 => xof!(KmacXof256),
    }
    Ok(out)
}
fn retain<'a>(
    stream: Stream<'a>,
    input: Bits<'_>,
    width: usize,
    last: u8,
) -> Result<Retained<'a>, Error> {
    if stream.0.algorithm.fixed() {
        stream.finalize_bits(input, width, last)
    } else {
        stream.finalize_bits_xof(input)?.retain(width, last, true)
    }
}
#[test]
#[ignore = "requires reviewed development-signed version-eight worker on native Windows VBS"]
fn development_kmac_streaming_campaign() -> Result<(), Box<dyn std::error::Error>> {
    let location = std::path::PathBuf::from(std::env::var("BRYNJA_ENCLAVE_KMAC_IMAGE")?);
    let expected = std::env::var("BRYNJA_ENCLAVE_KMAC_SHA256")?;
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
    let transport = Transport::development(&location, &policy)?;
    let mut session = Session(Owner {
        transport,
        state: State::Ready,
        sequence: 0,
        thread_bound: PhantomData,
    });
    let algorithms = [
        Algorithm::Kmac128,
        Algorithm::Kmac256,
        Algorithm::KmacXof128,
        Algorithm::KmacXof256,
    ];
    let mut cases = 0_usize;
    for algorithm in algorithms {
        for length in [0, 1, 71, 72, 73, 135, 136, 137, 167, 168, 169, 1024, 2057] {
            for last in 1..=8 {
                let mut message = std::vec![0x37;length];
                let valid = if length == 0 { 0 } else { last };
                if let Some(tail) = message.last_mut() {
                    *tail &= u8::MAX
                        .checked_shr(u32::from(8_u8.checked_sub(valid).ok_or(Error::Bounds)?))
                        .ok_or(Error::Bounds)?;
                }
                let input = bits(&message, valid)?;
                let key = std::vec![1;if length==2057{2050}else{33}];
                let custom = std::vec![1;if length==2057{4097}else{3}];
                let key = bits(&key, 1)?;
                let custom = bits(&custom, last)?;
                let width = if algorithm.fixed() { 33 } else { 201 };
                let expected = reference(algorithm, key, custom, input, width, last)?;
                let mut stream = session.stream(algorithm, key, custom)?;
                stream.update(&[])?;
                let mut actual = std::vec![0xa5;width];
                assert!(
                    retain(stream, input, width, last)?
                        .declassify(&mut actual, PublicDeclassification::acknowledge())?
                        .is_none()
                );
                assert_eq!(actual.as_slice(), expected.as_slice());
                assert_eq!(session.state(), State::Ready);
                if algorithm.fixed() {
                    assert!(
                        retain(session.stream(algorithm, key, custom)?, input, width, last)?
                            .verify(bits(&expected, last)?)?
                    );
                    let mut bad = expected;
                    *bad.first_mut().ok_or(Error::Bounds)? ^= 1;
                    assert!(
                        !retain(session.stream(algorithm, key, custom)?, input, width, last)?
                            .verify(bits(&bad, last)?)?
                    );
                    assert_eq!(session.state(), State::Ready);
                }
                cases = cases.checked_add(1).ok_or(Error::Bounds)?;
            }
        }
        println!("WINDOWS_ENCLAVE_KMAC_PROGRESS: cases={cases}");
    }
    let key = bits(&[0xa5; 32], 8)?;
    let input = bits(b"abc", 8)?;
    for source in algorithms {
        for target in algorithms {
            for last in 1..=8 {
                let expected_key = reference(source, key, empty()?, input, 33, last)?;
                let custom = std::vec![1;2050];
                let custom = bits(&custom, 1)?;
                let expected = reference(target, bits(&expected_key, last)?, custom, input, 33, 3)?;
                let stream = retain(session.stream(source, key, empty()?)?, input, 33, last)?
                    .rekey(target, custom)?;
                let mut actual = [0; 33];
                assert!(
                    retain(stream, input, 33, 3)?
                        .declassify(&mut actual, PublicDeclassification::acknowledge())?
                        .is_none()
                );
                assert_eq!(actual.as_slice(), expected.as_slice());
                cases = cases.checked_add(1).ok_or(Error::Bounds)?;
            }
        }
    }
    for algorithm in [Algorithm::KmacXof128, Algorithm::KmacXof256] {
        let expected = reference(algorithm, key, empty()?, input, 201, 3)?;
        let reader = session
            .stream(algorithm, key, empty()?)?
            .finalize_bits_xof(input)?;
        let reader = reader
            .retain(0, 0, false)?
            .declassify(&mut [], PublicDeclassification::acknowledge())?
            .ok_or(Error::Protocol)?;
        let mut actual = [0; 201];
        let reader = reader
            .retain(17, 8, false)?
            .declassify(
                actual.get_mut(..17).ok_or(Error::Bounds)?,
                PublicDeclassification::acknowledge(),
            )?
            .ok_or(Error::Protocol)?;
        assert!(
            reader
                .retain(184, 3, true)?
                .declassify(
                    actual.get_mut(17..).ok_or(Error::Bounds)?,
                    PublicDeclassification::acknowledge()
                )?
                .is_none()
        );
        assert_eq!(actual.as_slice(), expected.as_slice());
        cases = cases.checked_add(1).ok_or(Error::Bounds)?;
    }
    session
        .stream(Algorithm::Kmac128, key, empty()?)?
        .cancel()?;
    session
        .stream(Algorithm::KmacXof128, key, empty()?)?
        .finalize_xof()?
        .cancel()?;
    session
        .stream(Algorithm::KmacXof256, key, empty()?)?
        .finalize_xof()?
        .retain(1, 8, false)?
        .cancel()?;
    drop(session.stream(Algorithm::Kmac128, key, empty()?)?);
    assert_eq!(session.state(), State::Quarantined);
    session.close()?;
    println!(
        "WINDOWS_ENCLAVE_KMAC: PASS; cases={cases}; streamed_setup=PASS; retained_rekey=PASS; verification=PASS; abandonment=PASS; development_only=true"
    );
    Ok(())
}
