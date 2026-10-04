//! Synthetic PE metadata only: these bytes are not a signed executable.
use super::*;
fn put(b: &mut [u8], p: usize, value: &[u8]) -> Result<()> {
    b.get_mut(p..add(p, value.len())?)
        .ok_or(Error::Image)?
        .copy_from_slice(value);
    Ok(())
}
fn fixture() -> Result<Vec<u8>> {
    let mut b = vec![0; 4624];
    for (p, value) in [
        (0, b"MZ".as_slice()),
        (128, b"PE\0\0"),
        (392, b".rdata"),
        (1920, b"ucrtbase_enclave.dll\0"),
        (1952, b"vertdll.dll\0"),
        (2210, b"CallEnclave\0"),
        (1560, &[0x42]),
        (1576, &[0x50]),
    ] {
        put(&mut b, p, value)?;
    }
    for (p, value) in [
        (132, 0x8664u16),
        (134, 1),
        (148, 240),
        (150, 0x2022),
        (152, 0x20b),
        (222, 0x41e0),
        (4612, 0x200),
        (4614, 2),
    ] {
        put(&mut b, p, &value.to_le_bytes())?;
    }
    for (p, value) in [
        (60, 128u32),
        (208, 8192),
        (212, 512),
        (260, 16),
        (272, 4352),
        (276, 60),
        (296, 4608),
        (300, 16),
        (344, 4608),
        (348, 320),
        (400, 4096),
        (404, 4096),
        (408, 4096),
        (412, 512),
        (428, 0x40000040),
        (768, 5632),
        (780, 5504),
        (784, 5632),
        (788, 5696),
        (800, 5536),
        (804, 5696),
        (1024, 320),
        (1536, 80),
        (1540, 76),
        (1548, 2),
        (1552, 5248),
        (1556, 80),
        (1592, 1),
        (1596, 1),
        (1608, 1),
        (1612, 1),
        (1664, 2),
        (1736, 5504),
        (1744, 2),
        (1816, 5536),
        (4608, 16),
    ] {
        put(&mut b, p, &value.to_le_bytes())?;
    }
    for (p, value) in [
        (176, 0x180000000u64),
        (1272, 0x180001400),
        (1600, 0x10000000),
        (2048, 5792),
        (2112, 5792),
    ] {
        put(&mut b, p, &value.to_le_bytes())?;
    }
    Ok(b)
}
fn policy(b: &[u8]) -> Result<ImagePolicy> {
    let mut family = [0; 16];
    let mut image = [0; 16];
    put(&mut family, 0, &[0x42])?;
    put(&mut image, 0, &[0x50])?;
    Ok(ImagePolicy::reviewed_sha256(
        *brynja_hash_sha2::sha256(b)
            .map_err(|_| Error::Image)?
            .as_bytes(),
        family,
        image,
        1,
        1,
        [0, 0],
    ))
}
#[test]
fn every_file_byte_and_reviewed_identity_are_bound() -> Result<()> {
    let b = fixture()?;
    let p = policy(&b)?;
    admit(&b, &p)?;
    for i in 0..b.len() {
        let mut changed = b.clone();
        *changed.get_mut(i).ok_or(Error::Image)? ^= 1;
        assert_eq!(admit(&changed, &p), Err(Error::Image));
    }
    for field in 0..5 {
        let mut p = policy(&b)?;
        match field {
            0 => p.family.fill(0x41),
            1 => p.image.fill(0x41),
            2 => p.version = 2,
            3 => p.security = 2,
            _ => p.minimum_import_security = [1, 1],
        }
        assert_eq!(admit(&b, &p), Err(Error::Image));
    }
    Ok(())
}
#[test]
fn malformed_metadata_rejects_even_with_matching_hash() -> Result<()> {
    let b = fixture()?;
    for n in 0..b.len() {
        let prefix = b.get(..n).ok_or(Error::Image)?;
        assert_eq!(admit(prefix, &policy(prefix)?), Err(Error::Image));
    }
    for (offset, value) in [
        (60, u32::MAX),
        (134, 0),
        (148, 0),
        (222, 0),
        (260, 17),
        (208, 0),
        (212, 0),
        (404, 0),
        (408, u32::MAX),
        (412, 0),
        (428, 0xa0000000),
        (272, 0),
        (276, 40),
        (772, 1),
        (776, 1),
        (780, 0),
        (800, 5504),
        (808, 1),
        (768, 0),
        (784, 0),
        (2048, u32::MAX),
        (2210, 0),
        (1024, 263),
        (1272, 0),
        (1536, 79),
        (1540, 81),
        (1544, 1),
        (1544, 2),
        (1548, 1),
        (1552, u32::MAX),
        (1556, 79),
        (1592, 0),
        (1596, 0),
        (1600, 0),
        (1608, 2),
        (1612, 0),
        (1664, 0),
        (1664, 4),
        (1672, 1),
        (1704, 1),
        (1720, 1),
        (1740, 1),
        (1816, 5504),
        (296, 4609),
        (300, 8),
        (4608, 7),
        (4612, 0),
    ] {
        let mut changed = b.clone();
        put(&mut changed, offset, &value.to_le_bytes())?;
        assert_eq!(
            admit(&changed, &policy(&changed)?),
            Err(Error::Image),
            "offset {offset}"
        );
    }
    for index in [9, 11, 13, 14] {
        let mut changed = b.clone();
        put(
            &mut changed,
            add(264, mul(8, index)?)?,
            &4096u32.to_le_bytes(),
        )?;
        assert_eq!(admit(&changed, &policy(&changed)?), Err(Error::Image));
    }
    Ok(())
}

#[test]
fn single_and_five_thread_admission_remain_exact_and_separate() -> Result<()> {
    for actual in [0_u32, 1, 2, 4, 5, 6, u32::MAX] {
        let mut b = fixture()?;
        put(&mut b, 1608, &actual.to_le_bytes())?;
        let p = policy(&b)?;
        assert_eq!(admit(&b, &p).is_ok(), actual == 1);
        for expected in [0_u32, 1, 2, 4, 5, 6, u32::MAX] {
            assert_eq!(
                admit_threads(&b, &p, expected).is_ok(),
                matches!(expected, 1 | 5) && actual == expected
            );
        }
        *b.get_mut(1608).ok_or(Error::Image)? ^= 1;
        assert!(admit_threads(&b, &p, 5).is_err());
    }
    Ok(())
}
