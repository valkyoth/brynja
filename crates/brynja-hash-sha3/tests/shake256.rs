//! Public SHAKE256 vectors, boundaries, domains, and incremental output.

mod support;

use brynja_hash_sha3::{
    ExtendableOutput, Shake256, Shake256Error, Update, XofReader, sha3_512, shake128, shake256,
};

#[test]
fn official_fips202_zero_and_1600_bit_vectors_match() {
    check(
        b"",
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
    );
    check(
        &[0xa3; 200],
        "cd8a920ed141aa0407a22d59288652e9d9f1a7ee0c1e7c1ca699424da84a904d2d700caae7396ece96604440577da4f3aa22aeb8857f961c4cd8e06f0ae6610b",
    );
}

#[test]
fn standard_text_and_million_byte_outputs_match() {
    let mut abc = [0_u8; 64];
    assert_eq!(shake256(b"abc", &mut abc), Ok(()));
    assert_eq!(
        abc,
        support::decode(
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"
        )
    );

    let mut state = Shake256::new();
    let chunk = [b'a'; 1_000];
    for _ in 0..1_000 {
        assert_eq!(state.update(&chunk), Ok(()));
    }
    let mut million = [0_u8; 64];
    assert_eq!(state.finalize_xof().squeeze(&mut million), Ok(()));
    assert_eq!(
        million,
        support::decode(
            "3578a7a4ca9137569cdf76ed617d31bb994fca9c1bbf8b184013de8234dfd13a3fd124d4df76c0a539ee7dd2f6e1ec346124c815d9410e145eb561bcd97b18ab"
        )
    );
}

#[test]
fn suffix_and_rate_boundaries_have_exact_output() {
    let message = support::patterned::<137>();
    for (length, output) in [
        (
            135,
            "c45dae624ad8a2f5aa7bac9d7557737fd91c96eedb70a6be5574d57a844eade07f4056bf081a1098101cea8132188c422136feb4687d1e2209f3fd28bedfb8f4",
        ),
        (
            136,
            "b7ff4073b3f5a8eabd6e17705ca7f6761a31058f9df781a6a47e3a3063b9d67a757e8dbf043dac48d2154e46d59c0b9e8bc36ba035153691fbe83b9eff5dae4a",
        ),
        (
            137,
            "01d90952c642a5eb2a8fc9d713f843a45d7ac05132dddcb2efc9bebc27e37bcbe42130c36f3540250ab11796980e773683f28d07f0f838606fb9c45e452bd38f",
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
    let message = support::patterned::<409>();
    let mut expected = [0_u8; 257];
    assert_eq!(shake256(&message, &mut expected), Ok(()));
    for chunk_size in 1..=149 {
        let mut state = Shake256::new();
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
    assert_eq!(shake256(b"abc", &mut expected), Ok(()));
    for chunk_size in 1..=157 {
        let mut state = Shake256::new();
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
    let mut state = Shake256::new();
    assert_eq!(state.check_additional_bytes(u128::MAX), Ok(()));
    assert_eq!(state.update(b"abc"), Ok(()));
    assert_eq!(state.message_bytes(), 3);
    assert_eq!(
        state.check_additional_bytes(u128::MAX),
        Err(Shake256Error::MessageTooLong)
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
        Err(Shake256Error::OutputTooLong)
    );
}

#[test]
fn shake_domain_is_distinct_from_fixed_output_sha3() {
    let mut output = [0_u8; 64];
    assert_eq!(shake256(b"", &mut output), Ok(()));
    let digest = sha3_512(b"");
    assert!(digest.is_ok());
    if let Ok(digest) = digest {
        assert_ne!(&output, digest.as_bytes());
    }
}

#[test]
fn shake_strength_identities_are_distinct() {
    let mut output128 = [0_u8; 64];
    let mut output256 = [0_u8; 64];
    assert_eq!(shake128(b"abc", &mut output128), Ok(()));
    assert_eq!(shake256(b"abc", &mut output256), Ok(()));
    assert_ne!(output128, output256);
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
    assert_eq!(shake256(b"abc", &mut expected), Ok(()));
    assert_eq!(
        xof_with_traits(Shake256::new(), b"abc", &mut actual),
        Ok(())
    );
    assert_eq!(actual, expected);
    assert_eq!(Shake256::MAX_MESSAGE_BYTES, u128::MAX);
}

fn check(input: &[u8], expected: &str) {
    let mut output = [0_u8; 64];
    assert_eq!(shake256(input, &mut output), Ok(()));
    assert_eq!(output, support::decode(expected));
}
