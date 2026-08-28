//! Public SHAKE128 vectors, boundaries, domains, and incremental output.

mod support;

use brynja_hash_sha3::{
    ExtendableOutput, Shake128, Shake128Error, Update, XofReader, sha3_256, shake128,
};

#[test]
fn official_fips202_zero_and_1600_bit_vectors_match() {
    check(
        b"",
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
    );
    check(
        &[0xa3; 200],
        "131ab8d2b594946b9c81333f9bb6e0ce75c3b93104fa3469d3917457385da037",
    );
}

#[test]
fn standard_text_and_million_byte_outputs_match() {
    let mut abc = [0_u8; 64];
    assert_eq!(shake128(b"abc", &mut abc), Ok(()));
    assert_eq!(
        abc,
        support::decode(
            "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc844c50af32acd3f2cdd066568706f509bc1bdde58295dae3f891a9a0fca578378"
        )
    );

    let mut state = Shake128::new();
    let chunk = [b'a'; 1_000];
    for _ in 0..1_000 {
        assert_eq!(state.update(&chunk), Ok(()));
    }
    let mut million = [0_u8; 64];
    assert_eq!(state.finalize_xof().squeeze(&mut million), Ok(()));
    assert_eq!(
        million,
        support::decode(
            "9d222c79c4ff9d092cf6ca86143aa411e369973808ef97093255826c5572ef58424c4b5c28475ffdcf981663867fec6321c1262e387bccf8ca676884c4a9d0c1"
        )
    );
}

#[test]
fn suffix_and_rate_boundaries_have_exact_output() {
    let message = support::patterned::<169>();
    for (length, output) in [
        (
            167,
            "1e552791cc4e93a0d4a8dc47ae49228c2faa869e40e628f6ace477aec3f1ca7aefe1c1245cf82c265168ad2985121aedd72335ae1187a36742c746cf2b40cb30",
        ),
        (
            168,
            "f15277eb61c4908d44a2853f3cde071ae2ed7a23461fbe162a1a98cf6875059c06ffeebfca31afd9976e5592a3e7e5e94a665a8befa4b64a7f089cc0f3572403",
        ),
        (
            169,
            "015be3338c986d9846affa0f94b4afc2a76bc289c709e1a596ec9eccf090a773e4d69101b3a0516bfc556ffb886673b491f447926204119fed2933aea2d6091a",
        ),
    ] {
        let input = message.get(..length);
        assert!(input.is_some());
        if let Some(input) = input {
            check(input, output);
        }
    }
}

#[test]
fn every_input_partition_matches_one_shot() {
    let message = support::patterned::<505>();
    let mut expected = [0_u8; 257];
    assert_eq!(shake128(&message, &mut expected), Ok(()));
    for chunk_size in 1..=181 {
        let mut state = Shake128::new();
        assert_eq!(state.update(&[]), Ok(()));
        for chunk in message.chunks(chunk_size) {
            assert_eq!(state.update(chunk), Ok(()));
            assert_eq!(state.update(&[]), Ok(()));
        }
        let mut actual = [0_u8; 257];
        assert_eq!(state.finalize_xof().squeeze(&mut actual), Ok(()));
        assert_eq!(actual, expected);
    }
}

#[test]
fn every_output_partition_matches_one_shot_across_permutations() {
    let mut expected = [0_u8; 343];
    assert_eq!(shake128(b"abc", &mut expected), Ok(()));
    for chunk_size in 1..=193 {
        let mut state = Shake128::new();
        assert_eq!(state.update(b"abc"), Ok(()));
        let mut reader = state.finalize_xof();
        let mut actual = [0_u8; 343];
        for chunk in actual.chunks_mut(chunk_size) {
            assert_eq!(reader.squeeze(chunk), Ok(()));
        }
        assert_eq!(actual, expected);
        assert_eq!(reader.output_bytes(), 343);
    }
}

#[test]
fn zero_length_and_checked_state_transitions_are_exact() {
    let mut state = Shake128::new();
    assert_eq!(state.check_additional_bytes(u128::MAX), Ok(()));
    assert_eq!(state.update(b"abc"), Ok(()));
    assert_eq!(state.message_bytes(), 3);
    assert_eq!(
        state.check_additional_bytes(u128::MAX),
        Err(Shake128Error::MessageTooLong)
    );

    let mut reader = state.finalize_xof();
    let mut empty = [];
    assert_eq!(reader.squeeze(&mut empty), Ok(()));
    assert_eq!(reader.output_bytes(), 0);
    assert_eq!(reader.check_additional_bytes(u128::MAX), Ok(()));
    let mut byte = [0_u8; 1];
    assert_eq!(reader.squeeze(&mut byte), Ok(()));
    assert_eq!(reader.output_bytes(), 1);
    assert_eq!(
        reader.check_additional_bytes(u128::MAX),
        Err(Shake128Error::OutputTooLong)
    );
}

#[test]
fn shake_domain_is_distinct_from_fixed_output_sha3() {
    let mut output = [0_u8; 32];
    assert_eq!(shake128(b"", &mut output), Ok(()));
    let digest = sha3_256(b"");
    assert!(digest.is_ok());
    if let Ok(digest) = digest {
        assert_ne!(&output, digest.as_bytes());
    }
}

#[test]
fn trait_api_and_algorithm_identity_are_exact() {
    fn xof_with_traits<H>(mut state: H, input: &[u8], output: &mut [u8]) -> Result<(), H::Error>
    where
        H: ExtendableOutput,
        H::Reader: XofReader<Error = H::Error>,
    {
        Update::update(&mut state, input)?;
        XofReader::squeeze(&mut ExtendableOutput::finalize_xof(state), output)
    }

    let mut expected = [0_u8; 64];
    let mut actual = [0_u8; 64];
    assert_eq!(shake128(b"abc", &mut expected), Ok(()));
    assert_eq!(
        xof_with_traits(Shake128::new(), b"abc", &mut actual),
        Ok(())
    );
    assert_eq!(actual, expected);
    assert_eq!(Shake128::MAX_MESSAGE_BYTES, u128::MAX);
}

fn check(input: &[u8], expected: &str) {
    let mut output = [0_u8; 32];
    assert_eq!(shake128(input, &mut output), Ok(()));
    assert_eq!(output, support::decode(expected));
}
