//! Public SHA3-256 vectors, boundaries, domain separation, and streaming.

mod support;

use brynja_hash_sha3::{FixedOutput, Sha3_256, Sha3_256Digest, Update, sha3_256};

#[test]
fn official_fips202_zero_and_1600_bit_vectors_match() {
    check(
        b"",
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
    );
    check(
        &[0xa3; 200],
        "79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787",
    );
}

#[test]
fn standard_text_and_million_byte_vectors_match() {
    check(
        b"abc",
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
    );
    let chunk = [b'a'; 1_000];
    let mut state = Sha3_256::new();
    for _ in 0..1_000 {
        assert_eq!(state.update(&chunk), Ok(()));
    }
    assert_eq!(
        state.finalize(),
        expected("5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1")
    );
}

#[test]
fn suffix_and_rate_boundaries_have_exact_digests() {
    let message = support::patterned::<137>();
    for (length, digest) in [
        (
            135,
            "fded8fd9d6551c601eeb3b7c6bc5e5cfd8aad1d015b7e9aaa9c9b9475231d5e2",
        ),
        (
            136,
            "cf3ccff92480a29160c2d38317c430e14749bfee1788106957dfe73f8c4930e5",
        ),
        (
            137,
            "ce9d7dc90913ee5d92745019479a5352c6d6279bef18ed07dc0a83ee8084daca",
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
    let message = support::patterned::<409>();
    let expected = sha3_256(&message);
    assert!(expected.is_ok());
    for chunk_size in 1..=152 {
        let mut state = Sha3_256::new();
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
    let raw_keccak_empty =
        support::decode::<32>("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    let digest = sha3_256(b"");
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

    assert_eq!(hash_with_traits(Sha3_256::new(), b"abc"), sha3_256(b"abc"));
    assert_eq!(Sha3_256Digest::LENGTH, 32);
    assert_eq!(Sha3_256::new().message_bytes(), 0);
}

fn check(input: &[u8], digest: &str) {
    assert_eq!(sha3_256(input), Ok(expected(digest)));
}

fn expected(hex: &str) -> Sha3_256Digest {
    Sha3_256Digest::from_bytes(support::decode(hex))
}
