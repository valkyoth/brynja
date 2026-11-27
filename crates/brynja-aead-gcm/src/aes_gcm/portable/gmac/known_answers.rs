//! Public NIST GCMVS gcmEncryptExtIV128.rsp, Count=0, PTlen=0, AADlen=128.
//! The expected tags are fixed answers, not computed by the verifier.
use crate::gmac::{Aes128Gmac, GmacError, GmacTag};

#[test]
fn nist_96_bit_iv() -> Result<(), GmacError> {
    // IVlen=96, Taglen=128. Split the published IV at the reservation boundary.
    let key = 0x77be6370_8971c4e2_40d1cb79_e8d77febu128.to_be_bytes();
    let aad = 0x7a43ec1d_9c0a5a78_a0b16533_a6213cabu128.to_be_bytes();
    let expected = 0x209fcc8d_3675ed93_8e9c7166_709dd946u128.to_be_bytes();
    let iv = [
        0xe0, 0xe0, 0x0f, 0x19, 0xfe, 0xd7, 0xba, 0x01, 0x36, 0xa7, 0x97, 0xf3,
    ];
    let [a, b, c, d, counter @ ..] = iv;
    let mut schedule = [0; 176];
    {
        let mut sender = Aes128Gmac::<16>::from_reserved_range(
            &key,
            &mut schedule,
            [a, b, c, d],
            u64::from_be_bytes(counter),
            1,
        )?;
        let (issued, tag) = sender.authenticate_next(&aad)?;
        assert_eq!(issued, iv);
        assert_eq!(tag.as_bytes(), &expected);
    }
    let verifier = Aes128Gmac::<16>::for_verify(&key, &mut schedule)?;
    let tag = GmacTag::from_bytes(expected);
    verifier.verify(&iv, &aad, &tag)?;
    assert_eq!(
        verifier.verify(&iv, &[0; 16], &tag),
        Err(GmacError::Authentication)
    );
    Ok(())
}

#[test]
fn nist_hashed_iv_truncated_tag() -> Result<(), GmacError> {
    // IVlen=8, Taglen=96. The IV must pass through GHASH, not the 96-bit shortcut.
    let key = 0x553b1705_5a29da86_3d835752_13c012c9u128.to_be_bytes();
    let aad = 0x5ca5f375_6fb37386_66d28bda_57361b00u128.to_be_bytes();
    let expected = [
        0xa9, 0x3b, 0x0d, 0xc0, 0x40, 0x86, 0xda, 0x30, 0x2d, 0x84, 0xd1, 0xf3,
    ];
    let mut schedule = [0; 176];
    let mut sender =
        Aes128Gmac::<12, 1>::from_reserved_invocations(&key, &mut schedule, &[], 0x72, 1)?;
    let (iv, tag) = sender.authenticate_next(&aad)?;
    assert_eq!(iv, [0x72]);
    assert_eq!(tag.as_bytes(), &expected);
    sender.verify(&iv, &aad, &GmacTag::from_bytes(expected))
}
