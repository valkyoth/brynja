use super::*;
fn empty() -> Result<Bits<'static>, Error> {
    Bits::new(&[], 0).map_err(|_| Error::Bounds)
}
use super::reference::reference;

fn case_body(
    s: &mut Session,
    plan: Plan,
    length: usize,
    last: u8,
    setup_length: usize,
) -> Result<usize, Error> {
    let mut batch = s.batch(plan, u64::MAX)?;
    let mut expected = [0; 1024];
    let mut offset = 0_usize;
    let mut count = 0_usize;
    let setup = std::vec![1;setup_length];
    for (slot, shape) in plan.slots().iter().enumerate() {
        let Some(shape) = shape else { continue };
        let mut input = std::vec![u8::try_from(slot).map_err(|_|Error::Bounds)?;length];
        if let Some(b) = input.last_mut() {
            *b = 1;
        }
        let last = if length == 0 { 0 } else { last };
        let name = if matches!(
            shape.algorithm(),
            Algorithm::Cshake128 | Algorithm::Cshake256
        ) && setup_length != 0
        {
            Bits::new(&setup, 3).map_err(|_| Error::Bounds)?
        } else {
            empty()?
        };
        let custom = if name.bit_len() != 0 {
            Bits::new(&setup, 5).map_err(|_| Error::Bounds)?
        } else {
            empty()?
        };
        let digest = reference(
            *shape,
            Bits::new(&input, last).map_err(|_| Error::Bounds)?,
            name,
            custom,
        )?;
        let end = offset.checked_add(digest.len()).ok_or(Error::Bounds)?;
        expected
            .get_mut(offset..end)
            .ok_or(Error::Bounds)?
            .copy_from_slice(&digest);
        offset = end;
        let mut item = batch.item_custom(name, custom)?;
        assert_eq!(item.slot(), slot);
        item.update(&[])?;
        let split = if slot.is_multiple_of(2) {
            length / 2
        } else {
            0
        };
        for chunk in input.get(..split).ok_or(Error::Bounds)?.chunks(113) {
            item.update(chunk)?;
        }
        item.finish_bits(input.get(split..).ok_or(Error::Bounds)?, last)?;
        count = count.checked_add(1).ok_or(Error::Bounds)?;
    }
    let retained = batch.seal()?;
    assert_eq!(retained.plan(), plan);
    assert_eq!(plan.output_bytes(), offset);
    let mut public = [0xa5; 1024];
    retained.declassify(&mut public, PublicDeclassification::acknowledge())?;
    assert_eq!(public, expected);
    assert_eq!(s.state(), State::Ready);
    Ok(count)
}
fn case(
    s: &mut Session,
    plan: Plan,
    length: usize,
    last: u8,
    setup_length: usize,
) -> Result<usize, Box<dyn std::error::Error>> {
    case_body(s, plan, length, last, setup_length).map_err(|error| {
        std::format!(
            "synthetic batch length={length}, last={last}, setup={setup_length}: {error:?}"
        )
        .into()
    })
}
#[test]
#[ignore = "requires reviewed development-signed version-eleven worker on native Windows VBS"]
fn development_sha3_batch_campaign() -> Result<(), Box<dyn std::error::Error>> {
    let (location, policy) = image("BRYNJA_ENCLAVE_SHA3_BATCH")?;
    campaign(Transport::development(&location, &policy)?, "scalar")
}
pub(super) fn image(
    prefix: &str,
) -> Result<(std::path::PathBuf, ImagePolicy), Box<dyn std::error::Error>> {
    let location = std::path::PathBuf::from(std::env::var(std::format!("{prefix}_IMAGE"))?);
    let expected = std::env::var(std::format!("{prefix}_SHA256"))?;
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
    let algorithms = [
        Algorithm::Sha3_224,
        Algorithm::Sha3_256,
        Algorithm::Sha3_384,
        Algorithm::Sha3_512,
        Algorithm::Shake128,
        Algorithm::Shake256,
        Algorithm::Cshake128,
        Algorithm::Cshake256,
    ];
    let mut shapes = [None; 8];
    for (out, (algorithm, width)) in shapes.iter_mut().zip(
        algorithms
            .into_iter()
            .zip([28, 32, 48, 64, 169, 137, 0, 33]),
    ) {
        *out = Some(Output::new(
            algorithm,
            width,
            if width == 0 {
                0
            } else if algorithm.width().is_some() {
                8
            } else {
                3
            },
        )?);
    }
    let mut batches = 0_usize;
    let mut digests = 0_usize;
    for length in [0, 1, 71, 72, 135, 136, 143, 144, 167, 168, 1024, 2049] {
        for last in [1, 7, 8] {
            digests = digests
                .checked_add(case(&mut session, Plan::new(shapes)?, length, last, 1)?)
                .ok_or(Error::Bounds)?;
            batches = batches.checked_add(1).ok_or(Error::Bounds)?;
        }
    }
    for mask in 1_u16..=255 {
        let mut slots = [None; 8];
        for (i, (out, shape)) in slots.iter_mut().zip(shapes).enumerate() {
            if mask & (1 << i) != 0 {
                *out = shape;
            }
        }
        digests = digests
            .checked_add(case(&mut session, Plan::new(slots)?, 3, 7, 1)?)
            .ok_or(Error::Bounds)?;
        batches = batches.checked_add(1).ok_or(Error::Bounds)?;
    }
    for algorithm in [
        Algorithm::Shake128,
        Algorithm::Shake256,
        Algorithm::Cshake128,
        Algorithm::Cshake256,
    ] {
        for bits in [0_usize, 1, 7, 8, 1088, 1344, 8191, 8192] {
            let mut slots = [None; 8];
            *slots.get_mut(0).ok_or(Error::Bounds)? = Some(Output::new(
                algorithm,
                bits.div_ceil(8),
                if bits == 0 {
                    0
                } else {
                    let tail = bits
                        .checked_sub(1)
                        .and_then(|value| value.checked_rem(8))
                        .and_then(|value| value.checked_add(1))
                        .ok_or(Error::Bounds)?;
                    u8::try_from(tail).map_err(|_| Error::Bounds)?
                },
            )?);
            digests = digests
                .checked_add(case(&mut session, Plan::new(slots)?, 137, 3, 2050)?)
                .ok_or(Error::Bounds)?;
            batches = batches.checked_add(1).ok_or(Error::Bounds)?;
        }
    }
    let plan = Plan::new(shapes)?;
    session.batch(plan, 0)?.cancel()?;
    let mut batch = session.batch(plan, 3)?;
    batch.item()?.finish_bits(b"abc", 8)?;
    core::mem::forget(batch.item()?);
    batch.cancel()?;
    assert_eq!(session.state(), State::Ready);
    let mut batch = session.batch(plan, 0)?;
    core::mem::forget(batch.item()?);
    assert!(batch.seal().is_err());
    assert_eq!(session.state(), State::Quarantined);
    session.close()?;
    assert_eq!(session.state(), State::Closed);
    println!(
        "WINDOWS_ENCLAVE_SHA3_BATCH: batches={batches}; digests={digests}; cancellation/forgotten-item=PASS; route={route}; development-only"
    );
    Ok(())
}
