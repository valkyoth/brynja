use super::*;
fn bits(input: &[u8], last: u8) -> Result<Bits<'_>, Error> {
    Bits::new(input, last).map_err(|_| Error::Bounds)
}
fn retain(stream: Stream<'_>, width: usize, last: u8) -> Result<Retained<'_>, Error> {
    if stream.0.algorithm.fixed() {
        stream.finalize(width, last)
    } else {
        stream.finalize_xof()?.retain(width, last, true)
    }
}
fn reference(
    algorithm: Algorithm,
    items: &[Bits<'_>],
    custom: Bits<'_>,
    width: usize,
    last: u8,
) -> Result<std::vec::Vec<u8>, Error> {
    use brynja_hash_tuple::*;
    let mut output = std::vec![0;width];
    let destination = Fips202Output::new(&mut output, last).map_err(|_| Error::Bounds)?;
    match algorithm {
        Algorithm::TupleHash128 => tuple_hash128_bits(items, custom, destination),
        Algorithm::TupleHash256 => tuple_hash256_bits(items, custom, destination),
        Algorithm::TupleHashXof128 => tuple_hash_xof128_bits(items, custom, destination),
        Algorithm::TupleHashXof256 => tuple_hash_xof256_bits(items, custom, destination),
    }
    .map_err(|_| Error::Protocol)?;
    Ok(output)
}
#[test]
#[ignore = "requires reviewed development-signed version-nine worker on native Windows VBS"]
fn development_tuplehash_streaming_campaign() -> Result<(), Box<dyn std::error::Error>> {
    let location = std::path::PathBuf::from(std::env::var("BRYNJA_ENCLAVE_TUPLEHASH_IMAGE")?);
    let expected = std::env::var("BRYNJA_ENCLAVE_TUPLEHASH_SHA256")?;
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
    let mut cases = 0_usize;
    for algorithm in [
        Algorithm::TupleHash128,
        Algorithm::TupleHash256,
        Algorithm::TupleHashXof128,
        Algorithm::TupleHashXof256,
    ] {
        for size in [0, 1, 135, 136, 167, 168, 1024, 2049] {
            for last in [1, 7, 8] {
                let input = std::vec![1;size];
                let custom = std::vec![1;2049];
                let custom = bits(&custom, 1)?;
                let input = bits(&input, if size == 0 { 0 } else { last })?;
                let empty = bits(&[], 0)?;
                let expected = reference(algorithm, &[empty, input], custom, 33, last)?;
                let mut stream = session.stream(algorithm, custom)?;
                stream.item(0)?.finish()?;
                let mut item = stream.item(u128::try_from(input.bit_len())?)?;
                item.update(input)?;
                item.finish()?;
                let result = retain(stream, 33, last)?;
                let mut actual = [0; 33];
                assert!(
                    result
                        .declassify(&mut actual, PublicDeclassification::acknowledge())?
                        .is_none()
                );
                assert_eq!(actual.as_slice(), expected);
                assert_eq!(session.state(), State::Ready);
                cases = cases.checked_add(1).ok_or(Error::Bounds)?;
            }
        }
    }
    // A forgotten item cannot become an implicit completed tuple item.
    let mut stream = session.stream(Algorithm::TupleHash128, bits(&[], 0)?)?;
    core::mem::forget(stream.item(1)?);
    assert!(stream.finalize(32, 8).is_err());
    assert_eq!(session.state(), State::Quarantined);
    session.close()?;
    assert_eq!(session.state(), State::Closed);
    println!("WINDOWS_ENCLAVE_TUPLEHASH: cases={cases}; forgotten-item rejected; development-only");
    Ok(())
}
