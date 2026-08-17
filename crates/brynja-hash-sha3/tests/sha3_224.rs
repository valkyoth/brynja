//! Public SHA3-224 vectors, boundaries, and consumer behavior.

mod support;

use brynja_hash_sha3::{FixedOutput, Sha3_224, Sha3_224Digest, Update, sha3_224};

#[test]
fn official_fips202_zero_and_1600_bit_vectors_match() {
    check(
        b"",
        "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
    );
    check(
        &[0xa3; 200],
        "9376816aba503f72f96ce7eb65ac095deee3be4bf9bbc2a1cb7e11e0",
    );
}

#[test]
fn standard_text_and_million_byte_vectors_match() {
    check(
        b"abc",
        "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
    );
    let chunk = [b'a'; 1_000];
    let mut state = Sha3_224::new();
    for _ in 0..1_000 {
        assert_eq!(state.update(&chunk), Ok(()));
    }
    assert_eq!(
        state.finalize(),
        expected("d69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c")
    );
}

#[test]
fn suffix_and_rate_boundaries_have_exact_digests() {
    let message = support::patterned::<145>();
    for (length, digest) in [
        (
            143,
            "64d0e8a1be3cf30ef6727b30a6e428f7f068d44634c943d277ad8e7f",
        ),
        (
            144,
            "5be75e6a08f19913a1d8036c056cc4556b98dc90aeca3f2a0664dedc",
        ),
        (
            145,
            "90b861ac1b1598459ad8337afa9933ce2f1a6f972c57daf8fc2737e4",
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
    let message = support::patterned::<433>();
    let expected = sha3_224(&message);
    assert!(expected.is_ok());
    for chunk_size in 1..=160 {
        let mut state = Sha3_224::new();
        assert_eq!(state.update(&[]), Ok(()));
        for chunk in message.chunks(chunk_size) {
            assert_eq!(state.update(chunk), Ok(()));
            assert_eq!(state.update(&[]), Ok(()));
        }
        assert_eq!(Ok(state.finalize()), expected);
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

    assert_eq!(hash_with_traits(Sha3_224::new(), b"abc"), sha3_224(b"abc"));
    assert_eq!(Sha3_224Digest::LENGTH, 28);
    assert_eq!(Sha3_224::new().message_bytes(), 0);
}

fn check(input: &[u8], digest: &str) {
    assert_eq!(sha3_224(input), Ok(expected(digest)));
}

fn expected(hex: &str) -> Sha3_224Digest {
    Sha3_224Digest::from_bytes(support::decode(hex))
}
