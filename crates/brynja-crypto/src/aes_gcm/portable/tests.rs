use super::*;
use crate::aes_gcm::tests::sample_iv;
use core::cell::Cell;
extern crate std;

#[cfg(all(
    feature = "aes-static-execution",
    feature = "ghash-runtime-execution",
    target_os = "linux",
    target_arch = "x86_64",
    target_feature = "aes",
    target_feature = "sse2"
))]
#[path = "x86_pair_tests.rs"]
mod x86_pair;

// Exercise the underlying construction for externally specified vector IVs.
// Production senders must not get this test-only nonce selection shortcut.
fn seal(
    key: &impl Forward,
    iv: &[u8],
    aad: &[u8],
    pt: &[u8],
    scratch: &mut [u8],
    dst: &mut [u8],
) -> Result<Block, Error> {
    let io = Buffers::Separate(pt, dst);
    let frame = io.frame(iv, aad, scratch)?;
    seal_admitted(key, iv, aad, io, scratch, frame, &policy::TagPolicy::new()?)
}
fn open(
    key: &impl Forward,
    iv: &[u8],
    aad: &[u8],
    ct: &[u8],
    tag: &Block,
    scratch: &mut [u8],
    dst: &mut [u8],
) -> Result<(), Error> {
    open_with(
        key,
        iv,
        aad,
        Buffers::Separate(ct, dst),
        scratch,
        tag,
        &policy::TagPolicy::new()?,
    )
}

fn hex<const N: usize>(s: &str) -> Result<[u8; N], Error> {
    let (pairs, tail) = s.as_bytes().as_chunks::<2>();
    if pairs.len() != N || !tail.is_empty() {
        return Err(Error::Invariant);
    }
    let bytes = pairs
        .iter()
        .map(|pair| {
            u8::from_str_radix(
                core::str::from_utf8(pair).map_err(|_| Error::Invariant)?,
                16,
            )
            .map_err(|_| Error::Invariant)
        })
        .collect::<Result<std::vec::Vec<_>, _>>()?;
    bytes.try_into().map_err(|_| Error::Invariant)
}

// NIST AES_GCM.pdf, Encrypt-Generate examples 1 and 5 at each width.
// Compare complete public ciphertext AND tag, not a Brynja round-trip.
fn published(key: &impl Forward, empty: &str, ciphertext: &str, tag: &str) -> Result<(), Error> {
    let iv = hex::<12>("cafebabefacedbaddecaf888")?;
    assert_eq!(
        seal(key, &iv, &[], &[], &mut [], &mut [])?,
        hex::<16>(empty)?
    );
    open(key, &iv, &[], &[], &hex(empty)?, &mut [], &mut [])?;
    let aad = hex::<20>("3ad77bb40d7a3660a89ecaf32466ef97f5d3d585")?;
    let p = hex::<60>(concat!(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72",
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
    ))?;
    let (mut work, mut dst) = ([0xcc; 60], [0x55; 60]);
    assert_eq!(
        seal(key, &iv, &aad, &p, &mut work, &mut dst)?,
        hex::<16>(tag)?
    );
    assert_eq!(dst, hex::<60>(ciphertext)?);
    assert_eq!(work, [0; 60]);
    open(
        key,
        &iv,
        &aad,
        &hex::<60>(ciphertext)?,
        &hex(tag)?,
        &mut work,
        &mut dst,
    )?;
    assert_eq!(dst, p);
    assert_eq!(work, [0; 60]);
    Ok(())
}

#[test]
fn nist_seal_open_empty_and_partial_at_all_widths() -> Result<(), Error> {
    let mut s128 = [0; 176];
    let k128 = Aes128ExpandedKey::new(&hex("feffe9928665731c6d6a8f9467308308")?, &mut s128)
        .map_err(Error::Aes)?;
    published(
        &k128,
        "3247184b3c4f69a44dbcd22887bbb418",
        concat!(
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e",
            "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
        ),
        "f07c2528eea2fca1211f905e1b6a881b",
    )?;
    let mut s192 = [0; 208];
    let k192 = Aes192ExpandedKey::new(
        &hex("feffe9928665731c6d6a8f9467308308feffe9928665731c")?,
        &mut s192,
    )
    .map_err(Error::Aes)?;
    published(
        &k192,
        "c835aa88aebbc94f5a02e179fdcfc3e4",
        concat!(
            "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c",
            "7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710"
        ),
        "93ea28c659e269902a80acd208e7fc80",
    )?;
    let mut s256 = [0; 240];
    let k256 = Aes256ExpandedKey::new(
        &hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")?,
        &mut s256,
    )
    .map_err(Error::Aes)?;
    published(
        &k256,
        "fd2caa16a5832e76aa132c1453eeda7e",
        concat!(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa",
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
        ),
        "e097195f4532da895fb917a5a55c6aa0",
    )
}

#[test]
fn hashed_iv_matches_independent_aead() -> Result<(), Error> {
    // Frozen Python cryptography AESGCM(bytes(range(16))).encrypt(
    //     bytes(range(8)), bytes(range(17)), b"header"); no test dependency.
    let mut storage = [0; 176];
    let key = Aes128ExpandedKey::new(&hex("000102030405060708090a0b0c0d0e0f")?, &mut storage)
        .map_err(Error::Aes)?;
    let mut work = [0; 17];
    let mut dst = [0; 17];
    let tag = seal(
        &key,
        &hex::<8>("0001020304050607")?,
        b"header",
        &hex::<17>("000102030405060708090a0b0c0d0e0f10")?,
        &mut work,
        &mut dst,
    )?;
    assert_eq!(dst, hex::<17>("c74a2d76f6d3544bbff1c7eea93f42837a")?);
    assert_eq!(tag, hex::<16>("c2ae65fb488413b67945e3581eb52351")?);
    assert_eq!(work, [0; 17]);
    Ok(())
}

struct FailAt<'a, K> {
    key: &'a K,
    remaining: Cell<usize>,
}
impl<K: Forward> Forward for FailAt<'_, K> {
    fn hash_route(&self) -> &impl HashRoute {
        self.key.hash_route()
    }
    fn encrypt<'a>(&self, input: &Block, out: &'a mut Block) -> Result<SecretBlock<'a>, Error> {
        self.remaining.set(
            self.remaining
                .get()
                .checked_sub(1)
                .ok_or(Error::Aes(aes::Error::SecretMemory))?,
        );
        self.key.encrypt(input, out)
    }
}

#[test]
fn subkey_derivation_error_never_starts_ghash_or_commits_output() -> Result<(), Error> {
    use crate::ghash::TEST_STARTS;
    struct RejectSubkey(Cell<usize>);
    impl Forward for RejectSubkey {
        fn hash_route(&self) -> &impl HashRoute {
            &PortableHash
        }
        fn encrypt<'a>(&self, input: &Block, _: &'a mut Block) -> Result<SecretBlock<'a>, Error> {
            assert_eq!(input, &[0; 16]); // AES_K(0), not a later mask or payload call
            self.0.set(self.0.get() + 1);
            Err(Error::Aes(aes::Error::SecretMemory))
        }
    }
    let mut schedule = [0; 176];
    let key = Aes128ExpandedKey::new(&[3; 16], &mut schedule).map_err(Error::Aes)?;
    let plain = [0x17; 17];
    let (mut work, mut ct, mut dst) = ([0; 17], [0; 17], [0; 17]);
    for (iv, expected_starts) in [(&sample_iv::<12>()[..], 1), (&sample_iv::<8>()[..], 2)] {
        // Positive controls: GHASH for the message, plus the general IV if used.
        TEST_STARTS.set(0);
        let tag = seal(&key, iv, b"aad", &plain, &mut work, &mut ct)?;
        assert_eq!(TEST_STARTS.get(), expected_starts);
        TEST_STARTS.set(0);
        open(&key, iv, b"aad", &ct, &tag, &mut work, &mut dst)?;
        assert_eq!(dst, plain);
        assert_eq!(TEST_STARTS.get(), expected_starts);

        for opening in [false, true] {
            let fail = RejectSubkey(Cell::new(0));
            work.fill(0xcc);
            dst.fill(0x55);
            TEST_STARTS.set(0);
            let result = if opening {
                open(&fail, iv, b"aad", &ct, &tag, &mut work, &mut dst)
            } else {
                seal(&fail, iv, b"aad", &plain, &mut work, &mut dst).map(|_| ())
            };
            assert_eq!(result, Err(Error::Aes(aes::Error::SecretMemory)));
            assert_eq!(fail.0.get(), 1);
            assert_eq!(TEST_STARTS.get(), 0);
            assert_eq!(dst, [0x55; 17]);
            assert_eq!(work, [0; 17]);
        }
    }
    Ok(())
}

#[test]
fn rejection_and_late_failure_never_publish_partial_ciphertext() -> Result<(), Error> {
    let mut storage = [0; 176];
    let key = Aes128ExpandedKey::new(&[0; 16], &mut storage).map_err(Error::Aes)?;
    let (mut work, mut dst) = ([0xcc; 17], [0x55; 17]);
    for (iv, text_len, work_len, dst_len) in [
        (&[][..], 17, 17, 17),
        (&sample_iv::<1>()[..], 17, 16, 17),
        (&sample_iv::<1>()[..], 17, 17, 16),
    ] {
        assert_eq!(
            seal(
                &key,
                iv,
                b"aad",
                [1; 17].get(..text_len).ok_or(Error::Invariant)?,
                work.get_mut(..work_len).ok_or(Error::Invariant)?,
                dst.get_mut(..dst_len).ok_or(Error::Invariant)?
            ),
            Err(Error::Length)
        );
        assert_eq!(work, [0xcc; 17]);
        assert_eq!(dst, [0x55; 17]);
    }
    // H, mask, first payload block, then the partial second block.
    for pass_before_failure in 0..4 {
        let faulty = FailAt {
            key: &key,
            remaining: Cell::new(pass_before_failure),
        };
        work.fill(0xcc);
        assert_eq!(
            seal(
                &faulty,
                &sample_iv::<12>(),
                b"aad",
                &[1; 17],
                &mut work,
                &mut dst
            ),
            Err(Error::Aes(aes::Error::SecretMemory))
        );
        assert_eq!(dst, [0x55; 17]);
        assert_eq!(work, [0; 17]);
    }
    Ok(())
}

#[test]
fn invalid_tag_never_decrypts_and_late_errors_never_release_plaintext() -> Result<(), Error> {
    let mut storage = [0; 176];
    let key = Aes128ExpandedKey::new(&hex("000102030405060708090a0b0c0d0e0f")?, &mut storage)
        .map_err(Error::Aes)?;
    let (iv, ciphertext, tag) = (
        hex::<8>("0001020304050607")?,
        hex::<17>("c74a2d76f6d3544bbff1c7eea93f42837a")?,
        hex::<16>("c2ae65fb488413b67945e3581eb52351")?,
    );
    let (mut work, mut dst) = ([0xcc; 17], [0x55; 17]);
    let mut reject = |iv: &[u8], aad: &[u8], ct: &[u8], t: &Block| -> Result<(), Error> {
        // Two forward calls may derive H and the tag mask. Any attempted
        // payload decryption would instead produce an AES error.
        let only_auth = FailAt {
            key: &key,
            remaining: Cell::new(2),
        };
        work.fill(0xcc);
        assert_eq!(
            open(&only_auth, iv, aad, ct, t, &mut work, &mut dst),
            Err(Error::Authentication)
        );
        assert_eq!(only_auth.remaining.get(), 0);
        assert_eq!(work, [0; 17]);
        assert_eq!(dst, [0x55; 17]);
        Ok(())
    };
    for index in 0..16 {
        for bit in 0..8 {
            let mut altered = tag;
            *altered.get_mut(index).ok_or(Error::Invariant)? ^= 1u8 << bit;
            reject(&iv, b"header", &ciphertext, &altered)?;
        }
    }
    reject(&iv, b"headeR", &ciphertext, &tag)?;
    let mut wrong_iv = iv;
    wrong_iv[0] ^= 1;
    reject(&wrong_iv, b"header", &ciphertext, &tag)?;
    reject(&iv, b"header", &[0; 17], &tag)?;
    let late = FailAt {
        key: &key,
        remaining: Cell::new(3),
    };
    assert_eq!(
        open(
            &late,
            &iv,
            b"header",
            &ciphertext,
            &tag,
            &mut work,
            &mut dst
        ),
        Err(Error::Aes(aes::Error::SecretMemory))
    );
    assert_eq!(work, [0; 17]);
    assert_eq!(dst, [0x55; 17]);
    open(&key, &iv, b"header", &ciphertext, &tag, &mut work, &mut dst)?;
    assert_eq!(dst, hex::<17>("000102030405060708090a0b0c0d0e0f10")?);
    Ok(())
}
