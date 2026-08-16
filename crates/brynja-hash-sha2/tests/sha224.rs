//! Public SHA-224 known-answer, boundary, streaming, and trait acceptance.

use brynja_hash_sha2::{FixedOutput, Sha224, Sha224Digest, Update, sha224};

fn expected(text: &str) -> Sha224Digest {
    assert_eq!(text.len(), Sha224Digest::LENGTH.saturating_mul(2));
    let mut output = [0_u8; Sha224Digest::LENGTH];
    for (slot, pair) in output.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        if let [high, low] = pair {
            *slot = nibble(*high)
                .saturating_mul(16)
                .saturating_add(nibble(*low));
        }
    }
    Sha224Digest::from_bytes(output)
}

const fn nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte.saturating_sub(b'0'),
        b'a'..=b'f' => byte.saturating_sub(b'a').saturating_add(10),
        _ => 0,
    }
}

fn patterned(length: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(length);
    let mut generated = 0x1357_9bdf_u32;
    for _ in 0..length {
        generated = generated.wrapping_mul(73).wrapping_add(19);
        let [_, _, _, byte] = generated.to_be_bytes();
        output.push(byte);
    }
    output
}

#[test]
fn official_short_and_long_vectors_match_fips_and_nist_cavp() {
    let vectors = [
        (
            &b""[..],
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
        ),
        (
            &b"abc"[..],
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
        ),
        (
            &b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"[..],
            "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525",
        ),
        (
            &[0x84][..],
            "3cd36921df5d6963e73739cf4d20211e2d8877c19cff087ade9d0e3a",
        ),
    ];
    for (message, digest) in vectors {
        assert_eq!(sha224(message), Ok(expected(digest)));
    }
}

#[test]
fn official_million_a_vector_matches() {
    let message = vec![b'a'; 1_000_000];
    assert_eq!(
        sha224(&message),
        Ok(expected(
            "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67"
        ))
    );
}

#[test]
fn official_nist_cavp_monte_carlo_count_zero_matches() {
    let seed = expected("ed2b70d575d9d0b4196ae84a03eed940057ea89cdd729b95b7d4e6a5").into_bytes();
    let mut previous_3 = seed;
    let mut previous_2 = seed;
    let mut previous_1 = seed;
    for _ in 0..1_000 {
        let mut message = [0_u8; 84];
        for (part, previous) in message
            .chunks_exact_mut(28)
            .zip([previous_3, previous_2, previous_1])
        {
            part.copy_from_slice(&previous);
        }
        let digest = sha224(&message).map_or([0; 28], Sha224Digest::into_bytes);
        previous_3 = previous_2;
        previous_2 = previous_1;
        previous_1 = digest;
    }
    assert_eq!(
        Sha224Digest::from_bytes(previous_1),
        expected("cd94d7da13c030208b2d0d78fcfe9ea22fa8906df66aa9a1f42afa70")
    );
}

#[test]
fn every_padding_boundary_matches_independent_expected_results() {
    let vectors = [
        (
            55,
            "f1a1378b1d19e5ebb90f1d6c8d1235858f3f7a7dd3abea4724030499",
        ),
        (
            56,
            "e03bb450a865c701f65a923e99086ebe77cf5d2abbc7cf6ca357cde2",
        ),
        (
            63,
            "0753c69efa988a87efd79efe48543929e5a16aaa399429c490699148",
        ),
        (
            64,
            "f1066286a6b2522bdc5b8d1178b1c0fa7c6f43fd5d88749bd6f5d24f",
        ),
        (
            65,
            "c87062ef8e4ff677cfcb1b6250280b46c77deb389a62e157d3067939",
        ),
        (
            127,
            "a0d0cce61d50094d90f6bbb34bd9f921b3ad620b5566d6d54bd14d3a",
        ),
        (
            128,
            "c4083adb41f5eaef3ebe079aec55674b090e70558f3884f79be2f3ce",
        ),
        (
            129,
            "4a57dec62fde67250e7fa5e41efd28f0538209381e2f50991c881c70",
        ),
    ];
    for (length, digest) in vectors {
        assert_eq!(
            sha224(&patterned(length)),
            Ok(expected(digest)),
            "length {length}"
        );
    }
}

#[test]
fn every_two_part_split_and_fixed_chunk_width_matches_one_shot() {
    let message = patterned(257);
    let expected_digest = sha224(&message);
    assert!(expected_digest.is_ok());
    for split in 0..=message.len() {
        let first = message.get(..split);
        let second = message.get(split..);
        assert!(first.is_some());
        assert!(second.is_some());
        if let (Some(first), Some(second)) = (first, second) {
            let mut state = Sha224::new();
            assert_eq!(state.update(first), Ok(()));
            assert_eq!(state.update(second), Ok(()));
            assert_eq!(Ok(state.finalize()), expected_digest, "split {split}");
        }
    }
    for width in 1..=message.len() {
        let mut state = Sha224::new();
        for chunk in message.chunks(width) {
            assert_eq!(state.update(chunk), Ok(()));
        }
        assert_eq!(Ok(state.finalize()), expected_digest, "width {width}");
    }
}

#[test]
fn trait_api_and_checked_length_are_directly_usable() {
    fn absorb<T: Update>(state: &mut T, input: &[u8]) -> Result<(), T::Error> {
        state.update(input)
    }
    fn finish<T: FixedOutput>(state: T) -> T::Output {
        state.finalize()
    }

    let mut state = Sha224::default();
    assert_eq!(state.message_bytes(), 0);
    assert_eq!(state.check_additional_bytes(3), Ok(()));
    assert!(absorb(&mut state, b"abc").is_ok());
    assert_eq!(state.message_bytes(), 3);
    assert_eq!(Ok(finish(state)), sha224(b"abc"));

    let fresh = Sha224::new();
    assert!(
        fresh
            .check_additional_bytes(Sha224::MAX_MESSAGE_BYTES)
            .is_ok()
    );
    assert!(
        fresh
            .check_additional_bytes(Sha224::MAX_MESSAGE_BYTES + 1)
            .is_err()
    );
}

#[test]
fn sha224_is_not_truncated_sha256() {
    let sha224_bytes = sha224(b"abc").map(Sha224Digest::into_bytes);
    let sha256_bytes = brynja_hash_sha2::sha256(b"abc").map(|value| value.into_bytes());
    assert!(sha224_bytes.is_ok());
    assert!(sha256_bytes.is_ok());
    if let (Ok(sha224_bytes), Ok(sha256_bytes)) = (sha224_bytes, sha256_bytes) {
        assert_ne!(Some(sha224_bytes.as_slice()), sha256_bytes.get(..28));
    }
}
