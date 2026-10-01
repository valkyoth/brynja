use super::*;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn algorithm(value: &str) -> Result<Algorithm> {
    Ok(match value {
        "1" => Algorithm::ParallelHash128,
        "2" => Algorithm::ParallelHash256,
        "3" => Algorithm::ParallelHashXof128,
        "4" => Algorithm::ParallelHashXof256,
        _ => return Err("invalid vector identity".into()),
    })
}
fn bytes(value: &str) -> Result<std::vec::Vec<u8>> {
    if value == "-" {
        return Ok(std::vec::Vec::new());
    }
    if !value.len().is_multiple_of(2) {
        return Err("odd hex".into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|v| Ok(u8::from_str_radix(std::str::from_utf8(v)?, 16)?))
        .collect()
}
fn bits(input: &[u8], count: usize) -> Result<Bits<'_>> {
    if input.len() != count.div_ceil(8) {
        return Err("vector width".into());
    }
    Ok(Bits::new(
        input,
        if count == 0 {
            0
        } else {
            u8::try_from(
                count
                    .checked_sub(1)
                    .ok_or(Error::Bounds)?
                    .checked_rem(8)
                    .ok_or(Error::Bounds)?
                    .checked_add(1)
                    .ok_or(Error::Bounds)?,
            )?
        },
    )
    .map_err(|_| Error::Bounds)?)
}
fn empty() -> Result<Bits<'static>> {
    Ok(Bits::new(&[], 0).map_err(|_| Error::Bounds)?)
}
fn retain<'a>(stream: Stream<'a>, tail: Bits<'_>, width: usize, last: u8) -> Result<Retained<'a>> {
    Ok(if stream.0.algorithm.fixed() {
        stream.finalize(tail, width, last)?
    } else {
        stream.finalize_xof(tail)?.retain(width, last, true)?
    })
}
#[test]
#[ignore = "requires reviewed development-signed version-twelve worker on native Windows VBS"]
fn development_parallelhash_streaming_campaign() -> Result<()> {
    let (location, policy) = image("BRYNJA_ENCLAVE_PARALLEL")?;
    campaign(Transport::development(&location, &policy)?, "scalar")
}
pub(super) fn image(prefix: &str) -> Result<(std::path::PathBuf, ImagePolicy)> {
    let location = std::path::PathBuf::from(std::env::var(std::format!("{prefix}_IMAGE"))?);
    let digest = bytes(&std::env::var(std::format!("{prefix}_SHA256"))?)?;
    let digest: [u8; 32] = digest
        .try_into()
        .map_err(|_| "exact image digest required")?;
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
pub(super) fn campaign(transport: Transport, route: &str) -> Result<()> {
    let mut session = Session(Owner {
        transport,
        state: State::Ready,
        sequence: 0,
        thread_bound: PhantomData,
    });
    let vectors = std::fs::read_to_string(std::env::var("BRYNJA_ENCLAVE_PARALLEL_VECTORS")?)?;
    let mut direct = 0_usize;
    let mut retained = 0_usize;
    for line in vectors.lines() {
        let f = line.split_whitespace().collect::<std::vec::Vec<_>>();
        match f.as_slice() {
            ["D", id, block, cb, mb, last, custom, message, expected] => {
                let algorithm = algorithm(id)?;
                let custom = bytes(custom)?;
                let message = bytes(message)?;
                let expected = bytes(expected)?;
                let custom = bits(&custom, cb.parse()?)?;
                let input = bits(&message, mb.parse()?)?;
                let mut stream = session.stream(algorithm, block.parse()?, custom, u64::MAX)?;
                let complete = input.bit_len() / 8;
                for chunk in input
                    .as_bytes()
                    .get(..complete)
                    .ok_or(Error::Bounds)?
                    .chunks(113)
                {
                    stream.update(chunk)?;
                }
                let tail = bits(
                    input.as_bytes().get(complete..).ok_or(Error::Bounds)?,
                    input.bit_len() % 8,
                )?;
                let mut actual = std::vec![0;expected.len()];
                if algorithm.fixed() {
                    assert!(
                        stream
                            .finalize(tail, expected.len(), last.parse()?)?
                            .declassify(&mut actual, PublicDeclassification::acknowledge())?
                            .is_none()
                    );
                } else {
                    let mut reader = stream.finalize_xof(tail)?;
                    let mut position = 0;
                    while expected.len().checked_sub(position).ok_or(Error::Bounds)? > 31 {
                        let end = position.checked_add(31).ok_or(Error::Bounds)?;
                        reader = reader
                            .retain(31, 8, false)?
                            .declassify(
                                actual.get_mut(position..end).ok_or(Error::Bounds)?,
                                PublicDeclassification::acknowledge(),
                            )?
                            .ok_or(Error::Protocol)?;
                        position = end;
                    }
                    let destination = actual.get_mut(position..).ok_or(Error::Bounds)?;
                    assert!(
                        reader
                            .retain(destination.len(), last.parse()?, true)?
                            .declassify(destination, PublicDeclassification::acknowledge())?
                            .is_none()
                    );
                }
                assert_eq!(actual, expected, "{line}");
                direct = direct.checked_add(1).ok_or(Error::Bounds)?;
            }
            ["R", source, target, last, block, expected] => {
                let source = algorithm(source)?;
                let target = algorithm(target)?;
                let mut stream = session.stream(source, 8, empty()?, 3)?;
                stream.update(b"abc")?;
                let previous = retain(stream, empty()?, 33, last.parse()?)?;
                let finalized = previous.rehash(
                    target,
                    block.parse()?,
                    bits(&[19], 5)?,
                    34,
                    if target.fixed() { (33, 3) } else { (0, 0) },
                )?;
                let result = match finalized {
                    Finalized::Digest(r) => r,
                    Finalized::Reader(r) => r.retain(33, 3, true)?,
                };
                let mut actual = [0; 33];
                assert!(
                    result
                        .declassify(&mut actual, PublicDeclassification::acknowledge())?
                        .is_none()
                );
                assert_eq!(actual.as_slice(), bytes(expected)?, "{line}");
                retained = retained.checked_add(1).ok_or(Error::Bounds)?;
            }
            _ => return Err("malformed independent vector row".into()),
        }
        assert_eq!(session.state(), State::Ready);
    }
    assert_eq!((direct, retained), (332, 256));
    session
        .stream(Algorithm::ParallelHash128, 8, empty()?, 0)?
        .cancel()?;
    assert_eq!(session.state(), State::Ready);
    core::mem::forget(session.stream(Algorithm::ParallelHash128, 8, empty()?, 0)?);
    assert!(matches!(
        session.stream(Algorithm::ParallelHash128, 8, empty()?, 0),
        Err(Error::Busy)
    ));
    session.close()?;
    assert_eq!(session.state(), State::Closed);
    std::println!(
        "WINDOWS_PARALLELHASH_ENCLAVE: PASS; direct={direct}; retained={retained}; route={route}; development-only"
    );
    Ok(())
}
