//! Public SHA3-384 vectors, boundaries, domain separation, and streaming.

mod support;

use brynja_hash_sha3::{FixedOutput, Sha3_384, Sha3_384Digest, Update, sha3_384};

#[test]
fn official_fips202_zero_and_1600_bit_vectors_match() {
    check(
        b"",
        "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
    );
    check(
        &[0xa3; 200],
        "1881de2ca7e41ef95dc4732b8f5f002b189cc1e42b74168ed1732649ce1dbcdd76197a31fd55ee989f2d7050dd473e8f",
    );
}

#[test]
fn standard_text_and_million_byte_vectors_match() {
    check(
        b"abc",
        "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25",
    );
    let chunk = [b'a'; 1_000];
    let mut state = Sha3_384::new();
    for _ in 0..1_000 {
        assert_eq!(state.update(&chunk), Ok(()));
    }
    assert_eq!(
        state.finalize(),
        expected(
            "eee9e24d78c1855337983451df97c8ad9eedf256c6334f8e948d252d5e0e76847aa0774ddb90a842190d2c558b4b8340"
        )
    );
}

#[test]
fn suffix_and_rate_boundaries_have_exact_digests() {
    let message = support::patterned::<105>();
    for (length, digest) in [
        (
            103,
            "1f91ee551ad18f268876d1fc262f137fe196580216c5193819a95ec5222537d2a658dd129c3d8080e65ec7460f1f4704",
        ),
        (
            104,
            "5b8d0d5cf8b41be507be8fcbfcbdbac3a28eb368d430fed6780aaa78a93a8da4a6c50485949ca344f228be91a96005a3",
        ),
        (
            105,
            "4a2f0a8f2f1f4cc4605cc2537e0be28cf8b465c30f0a54b494a7128ec54ee4e85706b5e47a5697344d15cbf85680cd40",
        ),
    ] {
        let input = message.get(..length);
        assert!(input.is_some());
        if let Some(input) = input {
            check(input, digest);
        }
    }
}

#[test]
fn every_streaming_partition_matches_one_shot() {
    let message = support::patterned::<313>();
    let expected = sha3_384(&message);
    assert!(expected.is_ok());
    for chunk_size in 1..=120 {
        let mut state = Sha3_384::new();
        assert_eq!(state.update(&[]), Ok(()));
        for chunk in message.chunks(chunk_size) {
            assert_eq!(state.update(chunk), Ok(()));
            assert_eq!(state.update(&[]), Ok(()));
        }
        assert_eq!(Ok(state.finalize()), expected);
    }
}

#[test]
fn sha3_domain_is_not_raw_keccak() {
    let raw_keccak_empty = support::decode::<48>(
        "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff",
    );
    let digest = sha3_384(b"");
    assert!(digest.is_ok());
    if let Ok(digest) = digest {
        assert_ne!(digest.as_bytes(), &raw_keccak_empty);
    }
}

#[test]
fn trait_api_and_algorithm_identity_are_exact() {
    fn hash_with_traits<H>(mut state: H, input: &[u8]) -> Result<H::Output, H::Error>
    where
        H: FixedOutput,
    {
        Update::update(&mut state, input)?;
        Ok(FixedOutput::finalize(state))
    }

    assert_eq!(hash_with_traits(Sha3_384::new(), b"abc"), sha3_384(b"abc"));
    assert_eq!(Sha3_384Digest::LENGTH, 48);
    assert_eq!(Sha3_384::new().message_bytes(), 0);
}

fn check(input: &[u8], digest: &str) {
    assert_eq!(sha3_384(input), Ok(expected(digest)));
}

fn expected(hex: &str) -> Sha3_384Digest {
    Sha3_384Digest::from_bytes(support::decode(hex))
}
