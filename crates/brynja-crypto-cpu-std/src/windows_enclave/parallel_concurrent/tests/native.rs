use super::*;
type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>;
fn hex(text: &str) -> Result<Vec<u8>> {
    if text == "-" {
        return Ok(Vec::new());
    }
    if !text.len().is_multiple_of(2) {
        return Err("hex length".into());
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|s| Ok(u8::from_str_radix(std::str::from_utf8(s)?, 16)?))
        .collect()
}
fn failure(error: Error) -> Box<dyn std::error::Error> {
    format!("enclave error: {error:?}").into()
}
fn part(bytes: &[u8], bits: usize) -> Result<Part<'_>> {
    if bytes.len() != bits.div_ceil(8) {
        return Err("input width".into());
    }
    if bits.is_multiple_of(8) {
        return Part::bytes(bytes).map_err(failure);
    }
    let last = u8::try_from(bits.checked_sub(1).ok_or("bits")? % 8)?
        .checked_add(1)
        .ok_or("last")?;
    Part::bits(bytes, last).map_err(failure)
}
#[test]
#[ignore = "requires the reviewed five-thread development-signed image and oracle file on real Windows VBS"]
fn development_parallel_concurrent_host_campaign() -> Result<()> {
    let location = std::path::PathBuf::from(std::env::var("BRYNJA_PARALLEL_CONCURRENT_IMAGE")?);
    let digest = hex(&std::env::var("BRYNJA_PARALLEL_CONCURRENT_SHA256")?)?
        .try_into()
        .map_err(|_| "hash width")?;
    let mut family = [0; 16];
    family
        .get_mut(..4)
        .ok_or("family")?
        .copy_from_slice(b"BRYN");
    let mut image = [0; 16];
    image.get_mut(..4).ok_or("image")?.copy_from_slice(b"PAWV");
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
    // Matching digest cannot make a five-thread image valid for old one-thread APIs.
    assert_eq!(
        super::super::super::Session::open(&location, policy).err(),
        Some(Error::Image)
    );
    Transport::test_budget().map_err(failure)?;
    let vectors = std::fs::read_to_string(std::env::var("BRYNJA_PARALLEL_CONCURRENT_VECTORS")?)?;
    let mut cases = 0usize;
    for row in vectors.lines() {
        let [
            identity,
            block,
            input_bits,
            custom_bits,
            output_bits,
            message,
            custom,
            expected,
        ]: [&str; 8] = row
            .split_whitespace()
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| "oracle fields")?;
        let algorithm = match identity {
            "1" => Algorithm::ParallelHash128,
            "2" => Algorithm::ParallelHash256,
            "3" => Algorithm::ParallelHashXof128,
            "4" => Algorithm::ParallelHashXof256,
            _ => return Err("identity".into()),
        };
        let bits: usize = input_bits.parse()?;
        let cbits: usize = custom_bits.parse()?;
        let plan = Plan::new(algorithm, block.parse()?, output_bits.parse()?).map_err(failure)?;
        let message = hex(message)?;
        let custom = hex(custom)?;
        let expected = hex(expected)?;
        for corrupt in [0, 1, 2] {
            if (corrupt == 1 && bits.is_multiple_of(8)) || (corrupt == 2 && cbits.is_multiple_of(8))
            {
                continue;
            }
            let mut message = message.clone();
            let mut custom = custom.clone();
            if corrupt == 1 {
                *message.last_mut().ok_or("tail")? |= 128;
            }
            if corrupt == 2 {
                *custom.last_mut().ok_or("tail")? |= 128;
            }
            let input = || -> Result<Input<'_>> {
                Ok(Input::new(part(&message, bits)?, part(&custom, cbits)?))
            };
            let mut session = Session::from_transport(
                Transport::development(&location, policy).map_err(failure)?,
            );
            let mut wrong = [0x66; 1025];
            assert_eq!(
                session.digest_public(plan, input()?, &mut wrong, public()),
                Err(Error::Bounds)
            );
            assert_eq!(wrong, [0x66; 1025]);
            assert_eq!(session.state(), State::Ready);
            let width = plan.output_bytes();
            let end = width.checked_add(1).ok_or("width")?;
            let mut output = vec![0xa5; end.checked_add(1).ok_or("width")?];
            let result = session.digest_public(
                plan,
                input()?,
                output.get_mut(1..end).ok_or("range")?,
                public(),
            );
            assert!(session.0.channel.test_closed());
            if corrupt == 0 {
                result.map_err(failure)?;
                assert_eq!(output.get(1..end), Some(expected.as_slice()));
                assert_eq!(session.state(), State::Complete);
            } else {
                assert!(result.is_err());
                assert!(output.iter().all(|&b| b == 0xa5));
                assert_eq!(session.state(), State::Quarantined);
            }
            assert_eq!(output.first(), Some(&0xa5));
            assert_eq!(output.last(), Some(&0xa5));
            assert_eq!(
                session.digest_public(plan, input()?, &mut [], public()),
                Err(Error::Quarantined)
            );
            drop(session);
            cases = cases.checked_add(1).ok_or("count")?;
        }
    }
    assert_eq!(cases, 68);
    println!(
        "PARALLEL_CONCURRENT_HOST: cases={cases}; public+noncanonical; production signature rejected; PASS"
    );
    Ok(())
}
