//! Exercises only downstream-callable APIs. Native jobs must execute all
//! widths, not turn an unavailable pair into a successful skipped test.
#[cfg(not(any(
    all(
        all(
            target_arch = "x86_64",
            any(target_os = "linux", target_os = "windows")
        ),
        target_feature = "aes",
        target_feature = "sse2"
    ),
    all(
        all(
            target_arch = "aarch64",
            target_endian = "little",
            any(target_os = "linux", target_os = "macos")
        ),
        target_feature = "aes",
        target_feature = "neon"
    )
)))]
#[test]
fn unavailable_before_key_import() {
    use brynja_crypto::aes_gcm::execution::{AesPair, PairError};
    assert!(matches!(AesPair::require(), Err(PairError::Unavailable)));
}

#[cfg(any(
    all(
        all(
            target_arch = "x86_64",
            any(target_os = "linux", target_os = "windows")
        ),
        target_feature = "aes",
        target_feature = "sse2"
    ),
    all(
        all(
            target_arch = "aarch64",
            target_endian = "little",
            any(target_os = "linux", target_os = "macos")
        ),
        target_feature = "aes",
        target_feature = "neon"
    )
))]
mod native {
    mod vectors;
    use brynja_crypto::{
        aes_gcm::{self as gcm, GcmError},
        gmac::{self, GmacError, GmacTag},
    };
    fn detail(error: impl core::fmt::Debug) -> String {
        format!("{error:?}")
    }
    fn hex(s: &str) -> Result<Vec<u8>, String> {
        let (pairs, tail) = s.as_bytes().as_chunks::<2>();
        assert!(tail.is_empty());
        pairs
            .iter()
            .map(|p| {
                u8::from_str_radix(std::str::from_utf8(p).map_err(detail)?, 16).map_err(detail)
            })
            .collect()
    }
    macro_rules! width {
        ($test:ident, $gcm:ident, $mac:ident, $k:literal, $s:literal, $kat_key:expr, $tag:literal, $cases:ident) => {
            #[test]
            fn $test() -> Result<(), String> {
                let pair = gcm::execution::AesPair::require().map_err(detail)?;
                #[cfg(target_arch = "x86_64")]
                assert_eq!(pair.backend(), gcm::execution::PairBackend::AesNiPclmul);
                #[cfg(target_arch = "aarch64")]
                assert_eq!(pair.backend(), gcm::execution::PairBackend::ArmAesPmull);
                let (mut a, mut b, mut c, mut d) = ([0; $s], [0; $s], [0; $s], [0; $s]);
                fn known_open<const N: usize>(
                    pair: &gcm::execution::AesPair,
                    key: &[u8; $k],
                    iv: [u8; N],
                    aad: &[u8],
                    plaintext: &[u8],
                    (ciphertext, tag): (&str, u128),
                ) -> Result<(), String> {
                    let mut schedule = [0; $s];
                    let rx = gcm::execution::$gcm::<16, N>::for_open(pair, key, &mut schedule)
                        .map_err(detail)?;
                    let ciphertext = hex(ciphertext)?;
                    let mut data = ciphertext.clone();
                    let mut scratch = vec![0xa5; data.len()];
                    // For the padded 96-bit-IV case the empty-message tag is
                    // exactly the tag that a zero-returning GHASH would give
                    // under this same key and IV. It must not authenticate.
                    let wrong = if iv.as_slice() == vectors::IV12 {
                        $tag
                    } else {
                        tag ^ 1
                    };
                    assert_eq!(
                        rx.open_in_place(&iv, aad, &wrong.to_be_bytes(), &mut data, &mut scratch),
                        Err(GcmError::Authentication)
                    );
                    assert_eq!(data, ciphertext);
                    rx.open_in_place(&iv, aad, &tag.to_be_bytes(), &mut data, &mut scratch)
                        .map_err(detail)?;
                    assert_eq!(data, plaintext);
                    Ok(())
                }
                let [one, padded, short_iv, long_iv] = vectors::$cases;
                let aad = hex(vectors::AAD)?;
                let pt = hex(vectors::PLAINTEXT)?;
                known_open(&pair, &[0; $k], [0; 12], &[], &[0; 16], one)?;
                known_open::<12>(&pair, &$kat_key, vectors::IV12, &aad, &pt, padded)?;
                known_open::<8>(
                    &pair,
                    &$kat_key,
                    hex(vectors::IV8)?.try_into().map_err(detail)?,
                    &aad,
                    &pt,
                    short_iv,
                )?;
                known_open::<60>(
                    &pair,
                    &$kat_key,
                    hex(vectors::IV60)?.try_into().map_err(detail)?,
                    &aad,
                    &pt,
                    long_iv,
                )?;
                // NIST worked example 1 per width, also in the archive acceptance fixture.
                // Use the public 96-bit-IV shortcut; do not derive expectations from portable AES.
                {
                    let mut kat = gcm::execution::$gcm::<16>::from_reserved_range(
                        &pair,
                        &$kat_key,
                        &mut a,
                        0xcafebabe_u32.to_be_bytes(),
                        0xfacedbaddecaf888,
                        1,
                    )
                    .map_err(detail)?;
                    let (iv, tag) = kat
                        .seal_next_in_place(&[], &mut [], &mut [])
                        .map_err(detail)?;
                    assert_eq!(
                        iv,
                        [
                            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88
                        ]
                    );
                    let expected: u128 = $tag;
                    assert_eq!(tag, expected.to_be_bytes());
                    kat.open_in_place(&iv, &[], &tag, &mut [], &mut [])
                        .map_err(detail)?;
                    let verifier =
                        gmac::execution::$mac::<16>::for_verify(&pair, &$kat_key, &mut c)
                            .map_err(detail)?;
                    verifier
                        .verify(&iv, &[], &GmacTag::from_bytes(tag))
                        .map_err(detail)?;
                }
                // Synthetic fixture: equivalent routes over the same inputs.
                let key = [0x17; $k];
                let mut sender = gcm::execution::$gcm::<13, 8>::from_reserved_invocations(
                    &pair, &key, &mut a, b"test", 255, 2,
                )
                .map_err(detail)?;
                let mut oracle =
                    gcm::$gcm::<13, 8>::from_reserved_invocations(&key, &mut b, b"test", 255, 2)
                        .map_err(detail)?;
                let mut msg = [0x25; 21];
                let mut expected = msg;
                let mut scratch = [0xff; 21];
                assert_eq!(
                    sender.seal_next_in_place(b"aad", &mut msg, &mut []),
                    Err(GcmError::Length)
                );
                let (iv, tag) = sender
                    .seal_next_in_place(b"aad", &mut msg, &mut scratch)
                    .map_err(detail)?;
                assert_eq!(
                    (iv, tag),
                    oracle
                        .seal_next_in_place(b"aad", &mut expected, &mut scratch)
                        .map_err(detail)?
                );
                assert_eq!(msg, expected);
                let mut bad = tag;
                bad[0] ^= 1;
                assert_eq!(
                    sender.open_in_place(&iv, b"aad", &bad, &mut msg, &mut scratch),
                    Err(GcmError::Authentication)
                );
                assert_eq!(msg, expected);
                sender
                    .open_in_place(&iv, b"aad", &tag, &mut msg, &mut scratch)
                    .map_err(detail)?;
                assert_eq!(msg, [0x25; 21]);

                let mac_key = [0x61; $k];
                let mut mac = gmac::execution::$mac::<16>::from_reserved_range(
                    &pair, &mac_key, &mut c, *b"auth", 1, 2,
                )
                .map_err(detail)?;
                let mut mac_oracle =
                    gmac::$mac::<16>::from_reserved_range(&mac_key, &mut d, *b"auth", 1, 2)
                        .map_err(detail)?;
                let (nonce, t) = mac.authenticate_next(b"record").map_err(detail)?;
                let (n, reference) = mac_oracle.authenticate_next(b"record").map_err(detail)?;
                assert_eq!((nonce, t.as_bytes()), (n, reference.as_bytes()));
                assert_eq!(
                    mac.verify(&nonce, b"wrong", &t),
                    Err(GmacError::Authentication)
                );
                mac.verify(&nonce, b"record", &GmacTag::from_bytes(*t.as_bytes()))
                    .map_err(detail)?;

                pair.retire();
                scratch.fill(0xff);
                assert_eq!(
                    sender.seal_next_in_place(b"aad", &mut msg, &mut scratch),
                    Err(GcmError::Operation)
                );
                assert_eq!(msg, [0x25; 21]);
                assert_eq!(scratch, [0; 21]);
                assert_eq!(
                    sender.seal_next_in_place(b"aad", &mut msg, &mut scratch),
                    Err(GcmError::Exhausted)
                );
                assert_eq!(
                    mac.authenticate_next(b"record").err(),
                    Some(GmacError::Operation)
                );
                assert_eq!(
                    mac.authenticate_next(b"record").err(),
                    Some(GmacError::Exhausted)
                );
                drop((sender, mac));
                assert_eq!((a, c), ([0; $s], [0; $s]));
                a.fill(0x55);
                assert!(matches!(
                    gcm::execution::$gcm::<16>::for_open(&pair, &key, &mut a),
                    Err(GcmError::Operation)
                ));
                assert_eq!(a, [0; $s]);
                Ok(())
            }
        };
    }
    const KEY128: [u8; 16] = 0xfeffe9928665731c6d6a8f9467308308u128.to_be_bytes();
    width!(
        aes128,
        Aes128Gcm,
        Aes128Gmac,
        16,
        176,
        KEY128,
        0x3247184b3c4f69a44dbcd22887bbb418,
        AES128
    );
    width!(
        aes192,
        Aes192Gcm,
        Aes192Gmac,
        24,
        208,
        [
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
            0x83, 0x08, 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c
        ],
        0xc835aa88aebbc94f5a02e179fdcfc3e4,
        AES192
    );
    width!(
        aes256,
        Aes256Gcm,
        Aes256Gmac,
        32,
        240,
        [
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
            0x83, 0x08, 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
            0x67, 0x30, 0x83, 0x08
        ],
        0xfd2caa16a5832e76aa132c1453eeda7e,
        AES256
    );
}
