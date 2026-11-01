//! RFC 5869 A.4-A.7 and explicitly legacy-only ownership/limit regressions.
//! https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A
//! Non-RFC answers are frozen Python hmac.digest(..., 'sha1') answers for
//! the literal public test inputs; no production secret is formatted/copied here.

use brynja_legacy_hkdf::{Error, LegacyUse, MAX_OUTPUT_BYTES, Sha1Prk};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn answer(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[u8],
    expected_prk: &str,
    expected_okm: &str,
) -> Result<(), Error> {
    let mut storage = [0xa5; 20];
    let prk = Sha1Prk::extract(LegacyUse::acknowledge(), salt, ikm, &mut storage)?;
    assert_eq!(hex(prk.expose()), expected_prk);
    let mut output = vec![0xa5; expected_okm.len() / 2];
    let key = prk.expand(info, &mut output)?;
    assert_eq!(hex(key.expose()), expected_okm);
    drop(key);
    assert!(output.iter().all(|b| *b == 0));
    drop(prk);
    assert_eq!(storage, [0; 20]);
    Ok(())
}

#[test]
fn rfc5869_sha1_cases_four_through_seven() -> Result<(), Error> {
    answer(
        Some(&(0..=12).collect::<Vec<u8>>()),
        &[0x0b; 11],
        &(0xf0..=0xf9).collect::<Vec<u8>>(),
        "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243",
        "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896",
    )?;
    answer(
        Some(&(0x60..=0xaf).collect::<Vec<u8>>()),
        &(0..=0x4f).collect::<Vec<u8>>(),
        &(0xb0..=0xff).collect::<Vec<u8>>(),
        "8adae09a2a307059478d309b26c4115a224cfaf6",
        "0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4",
    )?;
    answer(
        Some(&[]),
        &[0x0b; 22],
        &[],
        "da8c8a73c7fa77288ec6f5e7c297786aa0d32d01",
        "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918",
    )?;
    answer(
        None,
        &[0x0c; 22],
        &[],
        "2adccada18779e7c2077ad2eb19d3f3e731385dd",
        "2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48",
    )
}

#[test]
fn empty_input_info_output_and_salt_choices() -> Result<(), Error> {
    for salt in [None, Some([].as_slice()), Some([0; 20].as_slice())] {
        let mut storage = [0; 20];
        let prk = Sha1Prk::extract(LegacyUse::acknowledge(), salt, &[], &mut storage)?;
        assert_eq!(
            hex(prk.expose()),
            "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d"
        );
        let mut empty = [];
        assert!(prk.expand(&[], &mut empty)?.expose().is_empty());
        let mut byte = [0xa5];
        assert_eq!(prk.expand(&[], &mut byte)?.expose().len(), 1);
        assert_eq!(byte, [0]);
    }
    Ok(())
}

#[test]
fn import_reuse_domain_separation_and_long_prk() -> Result<(), Error> {
    let mut storage = [0; 20];
    let prk = Sha1Prk::extract(
        LegacyUse::acknowledge(),
        Some(b"salt"),
        b"ikm",
        &mut storage,
    )?;
    let mut imported_storage = [0; 20];
    let imported = Sha1Prk::import(
        LegacyUse::acknowledge(),
        prk.expose(),
        &mut imported_storage,
    )?;
    let mut a = [0; 41];
    let mut b = [0; 41];
    let mut c = [0; 41];
    let key_a = prk.expand(b"a", &mut a)?;
    let key_b = imported.expand(b"a", &mut b)?;
    let key_c = prk.expand(b"b", &mut c)?;
    assert_eq!(key_a.expose(), key_b.expose());
    assert_ne!(key_a.expose(), key_c.expose());
    let mut long_storage = [0; 80];
    let long = Sha1Prk::import(LegacyUse::acknowledge(), &[0x55; 80], &mut long_storage)?;
    let mut long_output = [0; 40];
    assert_eq!(
        hex(long.expand(b"context", &mut long_output)?.expose()),
        "c9cfe13e6f9a99cd0f4194e5e432d3cb3285f6f9b249e314fce63cce7a8a157272a092e58f75c176"
    );
    Ok(())
}

#[test]
fn public_length_rejections_preserve_destinations() -> Result<(), Error> {
    for length in [0, 19, 21] {
        let mut wrong = vec![0xa5; length];
        assert_eq!(
            Sha1Prk::extract(LegacyUse::acknowledge(), None, b"ikm", &mut wrong).err(),
            Some(Error::DestinationLength)
        );
        assert!(wrong.iter().all(|b| *b == 0xa5));
    }
    let mut wrong = [0xa5; 19];
    assert_eq!(
        Sha1Prk::import(LegacyUse::acknowledge(), &[1; 19], &mut wrong).err(),
        Some(Error::PrkLength)
    );
    assert_eq!(wrong, [0xa5; 19]);
    assert_eq!(
        Sha1Prk::import(LegacyUse::acknowledge(), &[1; 20], &mut wrong).err(),
        Some(Error::DestinationLength)
    );
    assert_eq!(wrong, [0xa5; 19]);
    let mut storage = [0; 20];
    let prk = Sha1Prk::extract(LegacyUse::acknowledge(), None, b"ikm", &mut storage)?;
    let mut too_long = [0xa5; 5101];
    assert_eq!(
        prk.expand(&[], &mut too_long).err(),
        Some(Error::OutputLength)
    );
    assert_eq!(too_long, [0xa5; 5101]);
    let mut valid = [0; 20];
    let _key = prk.expand(b"still usable", &mut valid)?;
    Ok(())
}

#[test]
fn exact_limit_counter_255_and_partial_blocks() -> Result<(), Error> {
    let mut storage = [0; 20];
    let prk = Sha1Prk::extract(
        LegacyUse::acknowledge(),
        Some(b"salt"),
        b"ikm",
        &mut storage,
    )?;
    assert_eq!(MAX_OUTPUT_BYTES, 5100);
    let mut output = [0; MAX_OUTPUT_BYTES];
    let key = prk.expand(b"context", &mut output)?;
    // Python SHA-1 HMAC recurrence with these inputs, range(1, 256).
    assert_eq!(
        hex(key.expose().get(5080..).ok_or(Error::SecretMemory)?),
        "1b5f090b4a9503493ad9861ab6b0dfeea020bf9d"
    );
    for length in [1, 19, 20, 21, 39, 40, 41, 5099] {
        let mut out = vec![0; length];
        let shorter = prk.expand(b"context", &mut out)?;
        assert_eq!(Some(shorter.expose()), key.expose().get(..length));
    }
    drop(key);
    assert_eq!(output, [0; MAX_OUTPUT_BYTES]);
    Ok(())
}

#[test]
fn disjoint_storage_and_drop_during_unwind() -> Result<(), Error> {
    let mut shared = [0x42; 93];
    let (input, rest) = shared.split_at_mut(32);
    let (storage, output) = rest.split_at_mut(20);
    {
        let prk = Sha1Prk::extract(LegacyUse::acknowledge(), None, input, storage)?;
        let _key = prk.expand(b"info", output)?;
    }
    assert_eq!(input, &[0x42; 32]);
    assert!(rest.iter().all(|b| *b == 0));
    let mut storage = [0xa5; 20];
    let mut output = [0xa5; 41];
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<(), Error> {
        let prk = Sha1Prk::extract(LegacyUse::acknowledge(), None, b"ikm", &mut storage)?;
        let _key = prk.expand(&[], &mut output)?;
        std::panic::resume_unwind(Box::new(()));
    }));
    assert!(result.is_err());
    assert_eq!(storage, [0; 20]);
    assert_eq!(output, [0; 41]);
    let mut storage = [0xa5; 82];
    let mut output = [0xa5; 3];
    let prk = Sha1Prk::import(LegacyUse::acknowledge(), &[0x55; 80], &mut storage[1..81])?;
    let exported = prk.expose().to_vec(); // Public test data only.
    assert!(prk.expand(b"clear", &mut output[1..2])?.clear().is_some());
    assert_eq!(output, [0xa5, 0, 0xa5]);
    assert!(prk.expand(&[], &mut [])?.clear().is_none());
    let _cleared = prk.clear();
    assert_eq!((storage[0], storage[81]), (0xa5, 0xa5));
    assert!(storage[1..81].iter().all(|b| *b == 0));
    assert_eq!(exported, [0x55; 80]);
    let _cleared =
        Sha1Prk::import(LegacyUse::acknowledge(), &[0x42; 80], &mut storage[1..81])?.clear();
    assert!(storage[1..81].iter().all(|b| *b == 0));
    Ok(())
}
