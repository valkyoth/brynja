//! RFC 5869 A.1-A.3, independent SHA-2 answers and caller-owned HKDF lifecycle.
//! RFC vectors: https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A
//! Non-RFC answers were calculated with Python's OpenSSL-backed hmac.digest,
//! with literal salt/IKM/info below and T(i) = HMAC(PRK, T(i-1) || info || i).
//! Only public test material is formatted or copied into ordinary test Vecs.

use brynja_crypto::hkdf::{
    Algorithm, Error, ParameterError, Prk, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn answer<A: Algorithm>(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[u8],
    prk_hex: &str,
    okm_hex: &str,
) -> Result<(), Error> {
    let mut storage = vec![0xa5; A::TAG_BYTES];
    let mut output = vec![0xa5; okm_hex.len() / 2];
    let prk = Prk::<A>::extract(salt, ikm, &mut storage)?;
    assert_eq!(hex(prk.expose()), prk_hex);
    let key = prk.expand(info, &mut output)?;
    assert_eq!(hex(key.expose()), okm_hex);
    drop(key);
    assert!(output.iter().all(|b| *b == 0));
    drop(prk);
    assert!(storage.iter().all(|b| *b == 0));
    Ok(())
}

#[test]
fn rfc5869_sha256_cases_one_through_three() -> Result<(), Error> {
    answer::<Sha256>(
        Some(&(0..=12).collect::<Vec<u8>>()),
        &[0x0b; 22],
        &(0xf0..=0xf9).collect::<Vec<u8>>(),
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    )?;
    answer::<Sha256>(
        Some(&(0x60..=0xaf).collect::<Vec<u8>>()),
        &(0..=0x4f).collect::<Vec<u8>>(),
        &(0xb0..=0xff).collect::<Vec<u8>>(),
        "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
    )?;
    for salt in [Some([].as_slice()), None] {
        answer::<Sha256>(
            salt,
            &[0x0b; 22],
            &[],
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        )?;
    }
    Ok(())
}

#[test]
fn all_six_sha2_identities_match_independent_multiblock_answers() -> Result<(), Error> {
    let salt = Some(b"salt".as_slice());
    let ikm = b"input key material";
    let info = b"context";
    answer::<Sha224>(
        salt,
        ikm,
        info,
        "d4b84fdc213a138fc24e833be5f6d6de8f3e1b142116ec4be8161c50",
        "98952eddf677c2f4bf46b3480c77dca98eb4b35113116efeddecc11436150b1d9b6de19860e6aaa750b47c9cd01a4d1e363d48058162d6f5990e7704dd0f8350353c9c6636eda4260e",
    )?;
    answer::<Sha256>(
        salt,
        ikm,
        info,
        "4d6ccd983bd6ccd07adae83b28bb09e6d82b6d62bb7241f0dd6b111b2b5359a6",
        "790773b8093544d7052c18034ec05ddbf2753a2b9a23783a868b95143f51635725de7645b8581740526bac16a9fd4c69f4adfac2a37db3a2fe6eefc36f1e442c82b67d2602009b0305",
    )?;
    answer::<Sha384>(
        salt,
        ikm,
        info,
        "7ade0d5e869fec6327e2d46e2253a567c36ff2872edb0c997e4378441bc8fdc42973bbbb55b5305d0f9edfef9ba2036f",
        "0a5ae66322a4379b492406d826e76abb67b1e1135739c05ecec195bb9ce09990420098a806bfd177d32ec32d47e79f19e44abcb2c7b7292c2ebb910aa0c5a7129c00a5b026936e8634",
    )?;
    answer::<Sha512>(
        salt,
        ikm,
        info,
        "eb21b2c6b482ecc6346d064dc40ee40f96e8ef106d511617ab01ef74154438823d40e47ab56d99cedfc803b14d398541fdf15a103fbb72707cc449a1c88b1cdb",
        "0d91dde5b192629286a8a248069d686f5f88514fa6f0489c148f614dfae9830924b874f1d1c5de322428235486e7f47e2f4cc768641431387d2fe6a86682f9389ec9ce8dab0c448810",
    )?;
    answer::<Sha512_224>(
        salt,
        ikm,
        info,
        "f52a0a73014637a79c9be4f190afd5057355d6e2a5fa618e93cd28da",
        "85f5cb6f509d1baca7719e490d78d5e317f52a2951d17bc80f1ef13d227e8358fcf4c88217ba48df8acd44fea05d7196c944019caa6717a8951317934140ebcd0d69ab6d7996de2356",
    )?;
    answer::<Sha512_256>(
        salt,
        ikm,
        info,
        "b5713eba0a66d2ba1c1c13e5a0333d459d68d8dcb169e9dd2aa49a73456cd35c",
        "3cad6366cb324c1325a85673e32dc130754c89aa54d8398627380855e59ae2d152cd0722d75b549fe778b1c70a304c3afbebcc3dcaa568208650c3dc31b670fe264d624c11d251dc36",
    )
}

#[test]
fn empty_input_output_and_explicit_salts() -> Result<(), Error> {
    let mut a = [0; 32];
    let mut b = [0; 32];
    let mut c = [0; 32];
    let absent = Prk::<Sha256>::extract(None, &[], &mut a)?;
    assert_eq!(
        hex(absent.expose()),
        "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"
    );
    let empty = Prk::<Sha256>::extract(Some(&[]), &[], &mut b)?;
    let zero = Prk::<Sha256>::extract(Some(&[0; 32]), &[], &mut c)?;
    assert_eq!(absent.expose(), empty.expose());
    assert_eq!(absent.expose(), zero.expose());
    let mut out = [];
    assert!(absent.expand(&[], &mut out)?.expose().is_empty());
    let mut one = [0; 1];
    assert_eq!(absent.expand(&[], &mut one)?.expose().len(), 1);
    assert_eq!(one, [0]);
    Ok(())
}

#[test]
fn imported_prks_reuse_and_domain_separation() -> Result<(), Error> {
    let mut extracted_storage = [0; 32];
    let extracted = Prk::<Sha256>::extract(Some(b"salt"), b"ikm", &mut extracted_storage)?;
    let mut imported_storage = [0; 32];
    let imported = Prk::<Sha256>::import(extracted.expose(), &mut imported_storage)?;
    let mut a = [0; 65];
    let mut b = [0; 65];
    let mut c = [0; 65];
    let key_a = extracted.expand(b"a", &mut a)?;
    let key_b = imported.expand(b"a", &mut b)?;
    assert_eq!(key_a.expose(), key_b.expose());
    let key_c = extracted.expand(b"b", &mut c)?;
    assert_ne!(key_a.expose(), key_c.expose());
    let mut long_storage = [0; 80];
    let long = Prk::<Sha256>::import(&[0x55; 80], &mut long_storage)?;
    assert_eq!(long.expose(), &[0x55; 80]);
    let mut long_output = [0; 64];
    assert_eq!(
        hex(long.expand(b"context", &mut long_output)?.expose()),
        "74a4ec6c3fad6d35e2dce326d7538d1d151266bfca8655e1b0ae01d4f21a87dcceeab524e4383b8e9fb9a907d6d7683ca59c76b11d63443ccc144cbd28d5369e"
    );
    Ok(())
}

#[test]
fn public_rejections_leave_buffers_unchanged() -> Result<(), Error> {
    let mut wrong = [0xa5; 31];
    assert_eq!(
        Prk::<Sha256>::extract(None, b"ikm", &mut wrong).err(),
        Some(Error::DestinationLength)
    );
    assert_eq!(wrong, [0xa5; 31]);
    assert_eq!(
        Prk::<Sha256>::import(&[1; 31], &mut wrong).err(),
        Some(Error::PrkLength)
    );
    assert_eq!(wrong, [0xa5; 31]);
    assert_eq!(
        Prk::<Sha256>::import(&[1; 32], &mut wrong).err(),
        Some(Error::DestinationLength)
    );
    assert_eq!(wrong, [0xa5; 31]);
    let mut storage = [0; 32];
    let prk = Prk::<Sha256>::extract(None, b"ikm", &mut storage)?;
    let mut too_long = [0xa5; 8161];
    assert_eq!(
        prk.expand(&[], &mut too_long).err(),
        Some(Error::Parameters(ParameterError::ExpansionLength))
    );
    assert!(too_long.iter().all(|b| *b == 0xa5));
    let mut out = [0xa5; 32];
    assert_eq!(
        prk.expand_label(&[], &[], &mut out).err(),
        Some(Error::Parameters(ParameterError::LabelLength))
    );
    assert_eq!(out, [0xa5; 32]);
    assert_eq!(
        prk.expand_label(b"key", &[0; 256], &mut out).err(),
        Some(Error::Parameters(ParameterError::ContextLength))
    );
    assert_eq!(out, [0xa5; 32]);
    let _key = prk.expand(b"still usable", &mut out)?;
    Ok(())
}

#[test]
fn tls_expand_label_matches_independent_sha384_answer() -> Result<(), Error> {
    let mut storage = [0; 48];
    let prk = Prk::<Sha384>::extract(Some(b"salt"), b"input key material", &mut storage)?;
    let mut output = [0; 32];
    let key = prk.expand_label(b"key", b"abc", &mut output)?;
    assert_eq!(
        hex(key.expose()),
        "ef87e80909a27e763d047ffbbbf540acd17c1ed06d5a741b6a08e805fed34ebe"
    );
    Ok(())
}

#[test]
fn disjoint_allocation_and_unwind_cleanup() -> Result<(), Error> {
    let mut allocation = [0x42; 129];
    let (input, rest) = allocation.split_at_mut(32);
    let (prk_bytes, out) = rest.split_at_mut(32);
    {
        let prk = Prk::<Sha256>::extract(None, input, prk_bytes)?;
        let _key = prk.expand(b"context", out)?;
    }
    assert_eq!(input, &[0x42; 32]);
    assert!(rest.iter().all(|b| *b == 0));
    let mut storage = [0xa5; 32];
    let mut output = [0xa5; 65];
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<(), Error> {
        let prk = Prk::<Sha256>::extract(None, b"ikm", &mut storage)?;
        let _key = prk.expand(&[], &mut output)?;
        std::panic::resume_unwind(Box::new(()));
    }));
    assert!(result.is_err());
    assert_eq!(storage, [0; 32]);
    assert_eq!(output, [0; 65]);
    Ok(())
}

fn last_block<A: Algorithm>(expected: &str) -> Result<(), Error> {
    let mut storage = vec![0; A::TAG_BYTES];
    let prk = Prk::<A>::extract(Some(b"salt"), b"ikm", &mut storage)?;
    let limit = A::TAG_BYTES.checked_mul(255).ok_or(Error::SecretMemory)?;
    let mut output = vec![0; limit];
    let key = prk.expand(b"context", &mut output)?;
    let last_start = limit.checked_sub(A::TAG_BYTES).ok_or(Error::SecretMemory)?;
    assert_eq!(
        hex(key.expose().get(last_start..).ok_or(Error::SecretMemory)?),
        expected
    );
    for length in [
        1,
        A::TAG_BYTES.saturating_sub(1),
        A::TAG_BYTES,
        A::TAG_BYTES.saturating_add(1),
    ] {
        let mut shorter = vec![0; length];
        let prefix = prk.expand(b"context", &mut shorter)?;
        assert_eq!(Some(prefix.expose()), key.expose().get(..length));
    }
    let mut rejected = vec![0xa5; limit.saturating_add(1)];
    assert_eq!(
        prk.expand(b"context", &mut rejected).err(),
        Some(Error::Parameters(ParameterError::ExpansionLength))
    );
    assert!(rejected.iter().all(|b| *b == 0xa5));
    Ok(())
}

#[test]
fn all_identities_reach_counter_255_without_wrapping() -> Result<(), Error> {
    // Independent Python hmac.digest recurrence, salt="salt", IKM="ikm",
    // info="context", counters range(1, 256); these are the complete T(255).
    last_block::<Sha224>("703c6f5cd5a43f37a0aff47ed354ddfab7a531289e07b9eef4d4911b")?;
    last_block::<Sha256>("464703cef02f47b5832d1a9b7ac290bc986819abb427e68d48055d6cb7e34680")?;
    last_block::<Sha384>(
        "a7ad9ac06bad5d13eb7f7f9ccad2eda618d53d023138ca85bcbba58cbb4f5917f8dc28d1cd1c2add7ae8e75ee7f083ed",
    )?;
    last_block::<Sha512>(
        "1daead199bd11966c58506868d6719be2f9b53f1f0a92243420ba931947591218a6a860fdc4e9b4ebe770c827556c15f3601e1682b4525ced1d18e605ac1a6c5",
    )?;
    last_block::<Sha512_224>("a2683873133625d1d1d815b355885bdeee0ced96ce0b6717dc438a86")?;
    last_block::<Sha512_256>("be3f293020e88f8ccef78099765662edfe63b9ca4afd2488e994265b2c150c3a")
}
