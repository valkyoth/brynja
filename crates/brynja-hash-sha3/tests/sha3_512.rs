//! Public SHA3-512 vectors, boundaries, domain separation, and streaming.

mod support;

use brynja_hash_sha3::{FixedOutput, Sha3_512, Sha3_512Digest, Update, sha3_512};

#[test]
fn official_fips202_zero_and_1600_bit_vectors_match() {
    check(
        b"",
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
    );
    check(
        &[0xa3; 200],
        "e76dfad22084a8b1467fcf2ffa58361bec7628edf5f3fdc0e4805dc48caeeca81b7c13c30adf52a3659584739a2df46be589c51ca1a4a8416df6545a1ce8ba00",
    );
}

#[test]
fn standard_text_and_million_byte_vectors_match() {
    check(
        b"abc",
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
    );
    let chunk = [b'a'; 1_000];
    let mut state = Sha3_512::new();
    for _ in 0..1_000 {
        assert_eq!(state.update(&chunk), Ok(()));
    }
    assert_eq!(
        state.finalize(),
        expected(
            "3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87"
        )
    );
}

#[test]
fn suffix_and_rate_boundaries_have_exact_digests() {
    let message = support::patterned::<73>();
    for (length, digest) in [
        (
            71,
            "3ccc850d53a1287af7b4560b2ef0d43eb5d9a80d62a0e9cf1dbc040135921104d4395168e90bfc871773ebb34bca1bd67056e1cc7dc7a48ff7c3167d389f117c",
        ),
        (
            72,
            "5d63f2bbe971a983ac6847480106e4e1264ee3a0befd79954914e1d86e795b2e18238f12fc5e46cb9cc78efdec610a93647cc04e1c23d8caaa6a58c21dd26c07",
        ),
        (
            73,
            "921d9b7b2b0f3066a1646dbb058c979cb3925dec0f8c269faaa7f9648e73465ae55ec527257d5d5e1cfdbf5d6799bea1004b6186f5108c74e3b92fe924166558",
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
    let message = support::patterned::<289>();
    let expected = sha3_512(&message);
    assert!(expected.is_ok());
    for chunk_size in 1..=96 {
        let mut state = Sha3_512::new();
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
    let raw_keccak_empty = support::decode::<64>(
        "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e",
    );
    let digest = sha3_512(b"");
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

    assert_eq!(hash_with_traits(Sha3_512::new(), b"abc"), sha3_512(b"abc"));
    assert_eq!(Sha3_512Digest::LENGTH, 64);
    assert_eq!(Sha3_512::new().message_bytes(), 0);
}

fn check(input: &[u8], digest: &str) {
    assert_eq!(sha3_512(input), Ok(expected(digest)));
}

fn expected(hex: &str) -> Sha3_512Digest {
    Sha3_512Digest::from_bytes(support::decode(hex))
}
