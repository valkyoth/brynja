use super::*;
fn reference(algorithm: Algorithm, input: &[u8], last: u8) -> Result<std::vec::Vec<u8>, Error> {
    use brynja_hash_sha2::*;
    let input = BitString::new(input, last).map_err(|_| Error::Bounds)?;
    Ok(match algorithm.wire() {
        1 => sha224_bits(input)
            .map_err(|_| Error::Protocol)?
            .as_bytes()
            .to_vec(),
        2 => sha256_bits(input)
            .map_err(|_| Error::Protocol)?
            .as_bytes()
            .to_vec(),
        3 => sha384_bits(input)
            .map_err(|_| Error::Protocol)?
            .as_bytes()
            .to_vec(),
        4 => sha512_bits(input)
            .map_err(|_| Error::Protocol)?
            .as_bytes()
            .to_vec(),
        5 => sha512_224_bits(input)
            .map_err(|_| Error::Protocol)?
            .as_bytes()
            .to_vec(),
        6 => sha512_256_bits(input)
            .map_err(|_| Error::Protocol)?
            .as_bytes()
            .to_vec(),
        value => sha512_t_bits(
            Sha512TBits::new(u16::try_from(value & 0x1ff).map_err(|_| Error::Bounds)?)
                .map_err(|_| Error::Bounds)?,
            input,
        )
        .map_err(|_| Error::Protocol)?
        .as_bytes()
        .to_vec(),
    })
}
pub(super) fn case(s: &mut Session, plan: Plan, length: usize, last: u8) -> Result<usize, Error> {
    let mut batch = s.batch(
        plan,
        u64::try_from(length)
            .map_err(|_| Error::Bounds)?
            .checked_mul(8)
            .ok_or(Error::Bounds)?,
    )?;
    let mut expected = [0; 512];
    let mut count = 0_usize;
    for (slot, algorithm) in plan.slots().iter().enumerate() {
        let Some(algorithm) = algorithm else { continue };
        let mut input = std::vec![u8::try_from(slot).map_err(|_| Error::Bounds)?;length];
        if let Some(final_byte) = input.last_mut() {
            *final_byte = 0x80;
        }
        let last = if length == 0 { 0 } else { last };
        let digest = reference(*algorithm, &input, last)?;
        expected
            .chunks_exact_mut(64)
            .nth(slot)
            .ok_or(Error::Bounds)?
            .get_mut(..digest.len())
            .ok_or(Error::Bounds)?
            .copy_from_slice(&digest);
        let mut item = batch.item()?;
        assert_eq!(item.slot(), slot);
        item.update(&[])?;
        // Exercise the caller's large final-fragment chunking too.
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
    let mut public = [0xa5; 512];
    retained.declassify(&mut public, PublicDeclassification::acknowledge())?;
    assert_eq!(public, expected);
    assert_eq!(s.state(), State::Ready);
    Ok(count)
}
#[test]
#[ignore = "requires reviewed development-signed version-ten worker on native Windows VBS"]
fn development_sha2_batch_campaign() -> Result<(), Box<dyn std::error::Error>> {
    let location = std::path::PathBuf::from(std::env::var("BRYNJA_ENCLAVE_SHA2_BATCH_IMAGE")?);
    let expected = std::env::var("BRYNJA_ENCLAVE_SHA2_BATCH_SHA256")?;
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
    let mut batches = 0_usize;
    let mut digests = 0_usize;
    let algorithms = [
        Algorithm::SHA224,
        Algorithm::SHA256,
        Algorithm::SHA384,
        Algorithm::SHA512,
        Algorithm::SHA512_224,
        Algorithm::SHA512_256,
        Algorithm::sha512_t(1)?,
        Algorithm::sha512_t(511)?,
    ];
    for length in [0, 1, 55, 56, 63, 64, 111, 112, 127, 128, 1024, 2049] {
        for last in [1, 7, 8] {
            digests = digests
                .checked_add(case(
                    &mut session,
                    Plan::new(algorithms.map(Some))?,
                    length,
                    last,
                )?)
                .ok_or(Error::Bounds)?;
            batches = batches.checked_add(1).ok_or(Error::Bounds)?;
        }
    }
    for mask in 1_u16..=255 {
        let mut slots = [None; 8];
        for (slot, (output, algorithm)) in slots.iter_mut().zip(algorithms).enumerate() {
            if mask & (1 << slot) != 0 {
                *output = Some(algorithm);
            }
        }
        let plan = Plan::new(slots)?;
        digests = digests
            .checked_add(case(&mut session, plan, 3, 7)?)
            .ok_or(Error::Bounds)?;
        batches = batches.checked_add(1).ok_or(Error::Bounds)?;
    }
    let mut plan = [None; 8];
    let mut used = 0_usize;
    for t in (1..512).filter(|t| *t != 384) {
        *plan.get_mut(used).ok_or(Error::Bounds)? = Some(Algorithm::sha512_t(t)?);
        used = used.checked_add(1).ok_or(Error::Bounds)?;
        if used == 8 || t == 511 {
            digests = digests
                .checked_add(case(&mut session, Plan::new(plan)?, 3, 1)?)
                .ok_or(Error::Bounds)?;
            batches = batches.checked_add(1).ok_or(Error::Bounds)?;
            plan = [None; 8];
            used = 0;
        }
    }
    let plan = Plan::new([Some(Algorithm::SHA256); 8])?;
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
        "WINDOWS_ENCLAVE_SHA2_BATCH: batches={batches}; digests={digests}; cancellation/forgotten-item=PASS; scalar development-only"
    );
    Ok(())
}
