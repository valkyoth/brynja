//! RFC 2202's seven examples for each legacy construction.
use brynja_legacy_hmac::{Algorithm, Error, Hmac, LegacyUse, Md5, Sha1};

fn check<A: Algorithm>(key: &[u8], message: &[u8], hex: &str) -> Result<(), Error> {
    let expected: Vec<u8> = hex
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|[a, b]| {
            let nibble = |c: &u8| match c {
                b'0'..=b'9' => c.wrapping_sub(b'0'),
                b'a'..=b'f' => c.wrapping_sub(b'a').wrapping_add(10),
                _ => unreachable!(),
            };
            nibble(a).wrapping_mul(16) | nibble(b)
        })
        .collect();
    assert_eq!(expected.len(), A::TAG_BYTES);
    for width in 10..=A::TAG_BYTES {
        let prefix = expected.get(..width).ok_or(Error::TagLength)?;
        for chunk in [1, 7, 64, 1024] {
            let mut state = Hmac::<A>::with_tag_length(LegacyUse::acknowledge(), key, width)?;
            for part in message.chunks(chunk) {
                state.update(part)?;
            }
            let mut output = vec![0xa5; width];
            assert_eq!(state.finalize_tag(&mut output)?.as_bytes(), prefix);

            let mut secret = Hmac::<A>::with_tag_length(LegacyUse::acknowledge(), key, width)?;
            secret.update(message)?;
            {
                let tag = secret.finalize_secret(&mut output)?;
                assert_eq!(tag.expose(), prefix);
            }
            assert!(output.iter().all(|byte| *byte == 0));

            let mut verify = Hmac::<A>::with_tag_length(LegacyUse::acknowledge(), key, width)?;
            verify.update(message)?;
            assert_eq!(verify.verify(prefix), Ok(()));
        }
    }
    Ok(())
}

fn cases<A: Algorithm>(short: usize, expected: [&str; 7]) -> Result<(), Error> {
    let keys = [
        vec![0x0b; short],
        b"Jefe".to_vec(),
        vec![0xaa; short],
        (1..=25).collect(),
        vec![0x0c; short],
        vec![0xaa; 80],
        vec![0xaa; 80],
    ];
    let messages = [
        b"Hi There".to_vec(),
        b"what do ya want for nothing?".to_vec(),
        vec![0xdd; 50],
        vec![0xcd; 50],
        b"Test With Truncation".to_vec(),
        b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
        b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data".to_vec(),
    ];
    for ((key, message), digest) in keys.iter().zip(&messages).zip(expected) {
        check::<A>(key, message, digest)?;
    }
    Ok(())
}

#[test]
fn md5_all_seven_rfc_vectors_and_every_admitted_truncation() -> Result<(), Error> {
    cases::<Md5>(
        16,
        [
            "9294727a3638bb1c13f48ef8158bfc9d",
            "750c783e6ab0b503eaa86e310a5db738",
            "56be34521d144c88dbb8c733f0e8b3f6",
            "697eaf0aca3a3aea3a75164746ffaa79",
            "56461ef2342edc00f9bab995690efd4c",
            "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd",
            "6f630fad67cda0ee1fb1f562db3aa53e",
        ],
    )
}

#[test]
fn sha1_all_seven_rfc_vectors_and_every_admitted_truncation() -> Result<(), Error> {
    cases::<Sha1>(
        20,
        [
            "b617318655057264e28bc0b6fb378c8ef146be00",
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
            "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
            "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
            "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04",
            "aa4ae5e15272d00e95705637ce8a3b55ed402112",
            "e8e99d0f45237d786d6bbaa7965c7808bbff1a91",
        ],
    )
}
