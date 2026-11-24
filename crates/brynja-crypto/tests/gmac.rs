//! Public GMAC known-answer, rejection, and schedule ownership regressions.
#![cfg(feature = "gmac")]

use brynja_crypto::gmac::{Aes128Gmac, Aes192Gmac, Aes256Gmac, GmacError, GmacTag};

// Public fixtures: NIST GCMVS gcmEncryptExtIV{128,192,256}.rsp, Count=0,
// PTlen=0, AADlen=128, IVlen=96, Taglen=128; the short-IV case below uses
// IVlen=8, Taglen=96. Archive checksum is pinned in check-gcmvs.py.
fn bytes<const N: usize>(s: &str) -> Result<[u8; N], GmacError> {
    let (pairs, rest) = s.as_bytes().as_chunks::<2>();
    assert!(rest.is_empty());
    assert_eq!(pairs.len(), N);
    let mut out = [0; N];
    for (byte, pair) in out.iter_mut().zip(pairs) {
        *byte = u8::from_str_radix(
            std::str::from_utf8(pair).map_err(|_| GmacError::Length)?,
            16,
        )
        .map_err(|_| GmacError::Length)?;
    }
    Ok(out)
}

macro_rules! vector {
    ($owner:ident, $size:literal, $key:literal, $iv:literal, $aad:literal, $tag:literal) => {{
        let key = bytes($key)?;
        let iv = bytes::<12>($iv)?;
        let aad = bytes::<16>($aad)?;
        let tag = bytes::<16>($tag)?;
        let mut schedule = [0xa5; $size];
        {
            let [a, b, c, d, counter @ ..] = iv;
            let mut sender = $owner::<16>::from_reserved_range(
                &key,
                &mut schedule,
                [a, b, c, d],
                u64::from_be_bytes(counter),
                1,
            )?;
            let (issued, actual) = sender.authenticate_next(&aad)?;
            assert_eq!(issued, iv);
            assert_eq!(actual.as_bytes(), &tag);
            assert!(matches!(
                sender.authenticate_next(&aad),
                Err(GmacError::Exhausted)
            ));
        }
        assert_eq!(schedule, [0; $size]);
        let mut receiver = $owner::<16>::for_verify(&key, &mut schedule)?;
        let wire = GmacTag::from_bytes(tag);
        assert_eq!(receiver.verify(&iv, &aad, &wire), Ok(()));
        for i in 0..tag.len() {
            let mut bad = tag;
            *bad.get_mut(i).ok_or(GmacError::Length)? ^= 1;
            assert_eq!(
                receiver.verify(&iv, &aad, &GmacTag::from_bytes(bad)),
                Err(GmacError::Authentication)
            );
        }
        assert_eq!(
            receiver.verify(&iv, aad.get(1..).ok_or(GmacError::Length)?, &wire),
            Err(GmacError::Authentication)
        );
        let mut wrong_iv = iv;
        *wrong_iv.first_mut().ok_or(GmacError::Length)? ^= 1;
        assert_eq!(
            receiver.verify(&wrong_iv, &aad, &wire),
            Err(GmacError::Authentication)
        );
        assert!(matches!(
            receiver.authenticate_next(&aad),
            Err(GmacError::Exhausted)
        ));
    }};
}

#[test]
fn nist_aes128() -> Result<(), GmacError> {
    vector!(
        Aes128Gmac,
        176,
        "77be63708971c4e240d1cb79e8d77feb",
        "e0e00f19fed7ba0136a797f3",
        "7a43ec1d9c0a5a78a0b16533a6213cab",
        "209fcc8d3675ed938e9c7166709dd946"
    );
    Ok(())
}

#[test]
fn nist_aes192() -> Result<(), GmacError> {
    vector!(
        Aes192Gmac,
        208,
        "41c5da8667ef725220ffe39ae0ac590ac9fca729ab60ada0",
        "05ad13a5e2c2ab667e1a6fbc",
        "8b5c124bef6e2f0fe4d8c95cd5fa4cf1",
        "204bdb1bd62154bf08922aaa54eed705"
    );
    Ok(())
}

#[test]
fn nist_aes256() -> Result<(), GmacError> {
    vector!(
        Aes256Gmac,
        240,
        "78dc4e0aaf52d935c3c01eea57428f00ca1fd475f5da86a49c8dd73d68c8e223",
        "d79cf22d504cc793c3fb6c8a",
        "b96baa8c1c75a671bfb2d08d06be5f36",
        "3e5d486aa2e30b22e040b85723a06e76"
    );
    Ok(())
}

#[test]
fn nist_short_iv_and_tag() -> Result<(), GmacError> {
    let key = bytes("553b17055a29da863d83575213c012c9")?;
    let aad = bytes::<16>("5ca5f3756fb3738666d28bda57361b00")?;
    let iv = bytes::<1>("72")?;
    let [counter] = iv;
    let tag = bytes("a93b0dc04086da302d84d1f3")?;
    let mut schedule = [0; 176];
    let mut sender = Aes128Gmac::<12, 1>::from_reserved_invocations(
        &key,
        &mut schedule,
        &[],
        u32::from(counter),
        1,
    )?;
    let (issued, actual) = sender.authenticate_next(&aad)?;
    assert_eq!(issued, iv);
    assert_eq!(actual.as_bytes(), &tag);
    assert_eq!(sender.verify(&iv, &aad, &GmacTag::from_bytes(tag)), Ok(()));
    Ok(())
}

#[test]
fn rejects_invalid_policy_and_clears_on_failed_import() -> Result<(), GmacError> {
    let key = bytes("77be63708971c4e240d1cb79e8d77feb")?;
    let mut schedule = [0xa5; 176];
    assert!(matches!(
        Aes128Gmac::<11>::for_verify(&key, &mut schedule),
        Err(GmacError::TagLength)
    ));
    assert!(matches!(
        Aes128Gmac::<16, 0>::for_verify(&key, &mut schedule),
        Err(GmacError::Length)
    ));
    assert!(matches!(
        Aes128Gmac::<16, 1>::from_reserved_invocations(&key, &mut schedule, &[], 255, 2),
        Err(GmacError::Length)
    ));
    assert_eq!(schedule, [0; 176]);
    Ok(())
}
