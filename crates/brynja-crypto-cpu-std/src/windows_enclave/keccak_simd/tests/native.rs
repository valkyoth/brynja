use super::*;
fn hex(text: &str) -> Result<std::vec::Vec<u8>, Box<dyn std::error::Error>> {
    if text == "-" {
        return Ok(std::vec::Vec::new());
    }
    if !text.len().is_multiple_of(2) {
        return Err("odd hex".into());
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|s| Ok(u8::from_str_radix(std::str::from_utf8(s)?, 16)?))
        .collect()
}
fn policy(
    location: &str,
    hash: &str,
) -> Result<(std::path::PathBuf, &'static ImagePolicy), Box<dyn std::error::Error>> {
    let location = std::path::PathBuf::from(std::env::var(location)?);
    let digest: [u8; 32] = hex(&std::env::var(hash)?)?
        .try_into()
        .map_err(|_| "hash width")?;
    let mut family = [0; 16];
    family[..4].copy_from_slice(b"BRYN");
    let mut image = [0; 16];
    image[..4].copy_from_slice(b"PROB");
    Ok((
        location,
        Box::leak(Box::new(ImagePolicy::reviewed_sha256(
            digest,
            family,
            image,
            1,
            1,
            [0, 0],
        ))),
    ))
}
#[test]
#[ignore = "requires reviewed development-signed version-22 image and independent vectors on native Windows VBS"]
fn development_keccak_simd_host_campaign() -> Result<(), Box<dyn std::error::Error>> {
    let (location, p) = policy(
        "BRYNJA_ENCLAVE_KECCAK_SIMD_IMAGE",
        "BRYNJA_ENCLAVE_KECCAK_SIMD_SHA256",
    )?;
    assert_eq!(
        Session::open_avx2(&location, p).err(),
        Some(Error::Signature)
    );
    let mut wrong = ImagePolicy::reviewed_sha256([0; 32], p.family, p.image, 1, 1, [0, 0]);
    assert!(Transport::development(&location, &wrong).is_err());
    wrong.digest = p.digest;
    wrong.family = [0; 16];
    assert!(Transport::development(&location, &wrong).is_err());
    let (other, other_policy) = policy(
        "BRYNJA_ENCLAVE_OTHER_SIMD_IMAGE",
        "BRYNJA_ENCLAVE_OTHER_SIMD_SHA256",
    )?;
    assert!(Transport::development(&other, other_policy).is_err());
    let open = || Transport::development(&location, p).map(|t| Session(Owner::new(t)));
    let mut s = open()?;
    let vectors = std::fs::read_to_string(std::env::var("BRYNJA_KECCAK_SIMD_VECTORS")?)?;
    let lines: std::vec::Vec<_> = vectors.lines().collect();
    assert_eq!(lines.len(), 2080);
    let mut batches = 0_usize;
    for rows in lines.chunks_exact(4) {
        let mut slots = [Slot {
            algorithm: Algorithm::Sha3_256,
            output_bits: 256,
        }; 4];
        let mut data: [[std::vec::Vec<u8>; 3]; 4] =
            core::array::from_fn(|_| core::array::from_fn(|_| std::vec::Vec::new()));
        let mut last = [[0_u8; 3]; 4];
        let mut expected = [0; 1024];
        for ((((row, slot), lane_data), lane_last), output) in rows
            .iter()
            .zip(&mut slots)
            .zip(&mut data)
            .zip(&mut last)
            .zip(expected.chunks_exact_mut(256))
        {
            let f: [&str; 9] = row
                .split_whitespace()
                .collect::<std::vec::Vec<_>>()
                .try_into()
                .map_err(|_| "oracle columns")?;
            let algorithm = match f[0] {
                "1" => Algorithm::Sha3_224,
                "2" => Algorithm::Sha3_256,
                "3" => Algorithm::Sha3_384,
                "4" => Algorithm::Sha3_512,
                "5" => Algorithm::Shake128,
                "6" => Algorithm::Shake256,
                "7" => Algorithm::Cshake128,
                "8" => Algorithm::Cshake256,
                _ => return Err("oracle identity".into()),
            };
            let output_bits: usize = f[7].parse()?;
            *slot = Slot {
                algorithm,
                output_bits,
            };
            for ((fields, bytes), last) in [(f[1], f[2]), (f[3], f[4]), (f[5], f[6])]
                .into_iter()
                .zip(lane_data)
                .zip(lane_last)
            {
                let bits: usize = fields.0.parse()?;
                *bytes = hex(fields.1)?;
                assert_eq!(bytes.len(), bits.div_ceil(8));
                *last = if bits == 0 {
                    0
                } else {
                    u8::try_from((bits - 1) % 8 + 1)?
                };
            }
            let digest = hex(f[8])?;
            assert_eq!(digest.len(), output_bits.div_ceil(8));
            output
                .get_mut(..digest.len())
                .ok_or("output bounds")?
                .copy_from_slice(&digest);
        }
        let mut input = empty();
        for ((input, data), last) in input.iter_mut().zip(&data).zip(last) {
            *input = Input::new(
                Part::bits(&data[0], last[0]),
                Part::bits(&data[1], last[1]),
                Part::bits(&data[2], last[2]),
            );
        }
        let mut out = [0xa5; 1024];
        s.digest(Plan::new(slots)?, input, 10000)?
            .declassify(&mut out, PublicDeclassification::acknowledge())?;
        assert_eq!(out, expected, "batch {batches}");
        assert_eq!(s.state(), State::Ready);
        batches = batches.checked_add(1).ok_or("counter")?;
    }
    s.digest(plan()?, empty(), 100)?.cancel()?;
    let mut out = [0xa5; 1024];
    s.digest(plan()?, empty(), 100)?
        .declassify(&mut out, PublicDeclassification::acknowledge())?;
    let expected = hex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")?;
    for slot in out.chunks_exact(256) {
        assert_eq!(slot.get(..32).ok_or("output prefix")?, expected);
        assert_eq!(slot.get(32..).ok_or("output padding")?, &[0; 224]);
    }
    core::mem::forget(s.digest(plan()?, empty(), 100)?);
    assert!(matches!(s.digest(plan()?, empty(), 100), Err(Error::Busy)));
    s.close()?;
    let mut s = open()?;
    drop(s.digest(plan()?, empty(), 100)?);
    assert_eq!(s.state(), State::Quarantined);
    s.close()?;
    for kind in 0..4 {
        let mut s = open()?;
        if kind == 0 {
            assert!(s.digest(plan()?, empty(), 0).is_err());
        } else if kind == 1 {
            let bad = core::array::from_fn(|_| {
                Input::new(Part::bits(&[0x80], 1), Part::bytes(&[]), Part::bytes(&[]))
            });
            assert!(s.digest(plan()?, bad, 100).is_err());
        } else {
            let p = Plan::new(
                [Slot {
                    algorithm: Algorithm::Shake128,
                    output_bits: 7,
                }; 4],
            )?;
            let mut r = s.digest(p, empty(), 100)?;
            r.0.plan = Plan::new(
                [Slot {
                    algorithm: if kind == 2 {
                        Algorithm::Shake256
                    } else {
                        Algorithm::Shake128
                    },
                    output_bits: if kind == 3 { 8 } else { 7 },
                }; 4],
            )?;
            let mut out = [0xa5; 1024];
            assert!(
                r.declassify(&mut out, PublicDeclassification::acknowledge())
                    .is_err()
            );
            assert_eq!(out, [0xa5; 1024]);
        }
        assert_eq!(s.state(), State::Quarantined);
        assert!(matches!(
            s.digest(plan()?, empty(), 100),
            Err(Error::Quarantined)
        ));
        // Lost completion is terminal; no claim of verified mapping cleanup.
        assert_eq!(s.close(), Err(Error::Release));
    }
    assert_eq!(batches, 520);
    println!(
        "WINDOWS_ENCLAVE_KECCAK_SIMD_HOST: batches=521; digests=2084; trust/cancel/forget/quarantine/transactional=PASS; development_only=true"
    );
    Ok(())
}
