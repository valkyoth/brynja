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
    use brynja_crypto::{
        aes_gcm::{self as gcm, GcmError},
        gmac::{self, GmacError, GmacTag},
    };
    fn detail(error: impl core::fmt::Debug) -> String {
        format!("{error:?}")
    }
    macro_rules! width {
        ($test:ident, $gcm:ident, $mac:ident, $k:literal, $s:literal) => {
            #[test]
            fn $test() -> Result<(), String> {
                let pair = gcm::execution::AesPair::require().map_err(detail)?;
                #[cfg(target_arch = "x86_64")]
                assert_eq!(pair.backend(), gcm::execution::PairBackend::AesNiPclmul);
                #[cfg(target_arch = "aarch64")]
                assert_eq!(pair.backend(), gcm::execution::PairBackend::ArmAesPmull);
                let (mut a, mut b, mut c, mut d) = ([0; $s], [0; $s], [0; $s], [0; $s]);
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
    width!(aes128, Aes128Gcm, Aes128Gmac, 16, 176);
    width!(aes192, Aes192Gcm, Aes192Gmac, 24, 208);
    width!(aes256, Aes256Gcm, Aes256Gmac, 32, 240);
}
