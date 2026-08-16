//! Public SHA-384 known-answer, boundary, streaming, and trait acceptance.

use brynja_hash_sha2::{FixedOutput, Sha384, Sha384Digest, Sha384Error, Update, sha384};

const LONG_MESSAGE: &[u8] = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

fn expected(text: &str) -> Sha384Digest {
    assert_eq!(text.len(), Sha384Digest::LENGTH.saturating_mul(2));
    let mut output = [0_u8; Sha384Digest::LENGTH];
    for (slot, pair) in output.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        if let [high, low] = pair {
            *slot = nibble(*high)
                .saturating_mul(16)
                .saturating_add(nibble(*low));
        }
    }
    Sha384Digest::from_bytes(output)
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
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        ),
        (
            &b"abc"[..],
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        ),
        (
            LONG_MESSAGE,
            "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
        ),
        (
            &[0xc5][..],
            "b52b72da75d0666379e20f9b4a79c33a329a01f06a2fb7865c9062a28c1de860ba432edfd86b4cb1cb8a75b46076e3b1",
        ),
    ];
    for (message, digest) in vectors {
        assert_eq!(sha384(message), Ok(expected(digest)));
    }
}

#[test]
fn official_million_a_vector_matches() {
    let repeated = [b'a'; 1_000];
    let mut state = Sha384::new();
    for _ in 0..1_000 {
        assert_eq!(state.update(&repeated), Ok(()));
    }
    assert_eq!(
        state.finalize(),
        expected(
            "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985"
        )
    );
}

#[test]
fn official_nist_cavp_monte_carlo_count_zero_matches() {
    let seed = expected(
        "edff07255c71b54a9beae52cdfa083569a08be89949cbba73ddc8acf429359ca5e5be7a673633ca0d9709848f522a9df",
    )
    .into_bytes();
    let mut previous_3 = seed;
    let mut previous_2 = seed;
    let mut previous_1 = seed;
    for _ in 0..1_000 {
        let mut message = [0_u8; Sha384Digest::LENGTH * 3];
        for (part, previous) in message
            .chunks_exact_mut(Sha384Digest::LENGTH)
            .zip([previous_3, previous_2, previous_1])
        {
            part.copy_from_slice(&previous);
        }
        let digest = sha384(&message).map_or([0; Sha384Digest::LENGTH], Sha384Digest::into_bytes);
        previous_3 = previous_2;
        previous_2 = previous_1;
        previous_1 = digest;
    }
    assert_eq!(
        Sha384Digest::from_bytes(previous_1),
        expected(
            "e81b86c49a38feddfd185f71ca7da6732a053ed4a2640d52d27f53f9f76422650b0e93645301ac99f8295d6f820f1035"
        )
    );
}

#[test]
fn every_padding_boundary_matches_independent_expected_results() {
    let vectors = [
        (
            111,
            "45bd1127c65e5499595d742c6ff35d0a5fbf8ea2a1869f773f61b6ddaa717ce9e48c51f922ec3349c7f75a1744bd6248",
        ),
        (
            112,
            "f22f154eaee8439fef1f274a400501551c63336db98118fab21bf25b65f4b51dad4d8118cbe1a4f24cc90593cf21eceb",
        ),
        (
            127,
            "982952848f86b774aef900be46674e8ff28816454e750dfa0792c415f097366811fa03578be357f573a590297978b6f1",
        ),
        (
            128,
            "8a91a51cafa147e66cabcb97faefcaf544afa0f27b9c7ac20b401efcb360456e7c2c7c71a1fea6a53d451a07cbb65b1e",
        ),
        (
            129,
            "7f42d75b3181673efaa2eae008563d2fa865006be5fc6d441e1c1f02faf20bf36af1553ea35244d3f9a28029e0085c46",
        ),
        (
            255,
            "0a1e4d41d24de8e92f467fd3b3d4578239ecd0e6c3dd46412a6e7fcb47f52a25bb7d1721270a4d34ce175838c70492c3",
        ),
        (
            256,
            "c4ea96e56e4353b3c953959f21a85ac5c21a0b0cb4fc8a729c02d4d4da270b58ffa2963250957c351596a8141411c52f",
        ),
        (
            257,
            "5538e6b4e39e1ce80bb7ff6e99872b5609946b0954e4f8458fc6272629ae182aeccaa3bb5898493d1416213fe75ac6ce",
        ),
    ];
    for (length, digest) in vectors {
        assert_eq!(
            sha384(&patterned(length)),
            Ok(expected(digest)),
            "length {length}"
        );
    }
}

#[test]
fn every_two_part_split_and_fixed_chunk_width_matches_one_shot() {
    let message = patterned(257);
    let expected_digest = sha384(&message);
    assert!(expected_digest.is_ok());
    for split in 0..=message.len() {
        if let (Some(first), Some(second)) = (message.get(..split), message.get(split..)) {
            let mut state = Sha384::new();
            assert_eq!(state.update(first), Ok(()));
            assert_eq!(state.update(second), Ok(()));
            assert_eq!(Ok(state.finalize()), expected_digest, "split {split}");
        }
    }
    for width in 1..=message.len() {
        let mut state = Sha384::new();
        for chunk in message.chunks(width) {
            assert_eq!(state.update(chunk), Ok(()));
        }
        assert_eq!(Ok(state.finalize()), expected_digest, "width {width}");
    }
}

#[test]
fn trait_api_length_domain_and_real_content_are_usable() {
    fn absorb<T: Update>(state: &mut T, input: &[u8]) -> Result<(), T::Error> {
        state.update(input)
    }
    fn finish<T: FixedOutput>(state: T) -> T::Output {
        state.finalize()
    }

    let content = b"Brynja public SHA-384 consumer acceptance\n";
    let mut state = Sha384::default();
    assert_eq!(state.check_additional_bytes(content.len() as u128), Ok(()));
    assert!(absorb(&mut state, content).is_ok());
    assert_eq!(state.message_bytes(), content.len() as u128);
    assert_eq!(
        finish(state),
        expected(
            "d64806e2c1b7bdd6d89b3ab34040c9d77ffd5f7c18b67ad95f27a6c04282fcc56670e5810683042c2a3ed1524b79dea2"
        )
    );

    assert_eq!(
        Sha384::new().check_additional_bytes(Sha384::MAX_MESSAGE_BYTES),
        Ok(())
    );
    assert_eq!(
        Sha384::new().check_additional_bytes(Sha384::MAX_MESSAGE_BYTES + 1),
        Err(Sha384Error::MessageTooLong)
    );
}

#[test]
fn sha384_is_not_truncated_sha512() {
    let sha384_bytes = sha384(b"abc").map(Sha384Digest::into_bytes);
    let sha512_bytes = brynja_hash_sha2::sha512(b"abc").map(|value| value.into_bytes());
    assert!(sha384_bytes.is_ok());
    assert!(sha512_bytes.is_ok());
    if let (Ok(sha384_bytes), Ok(sha512_bytes)) = (sha384_bytes, sha512_bytes) {
        assert_ne!(Some(sha384_bytes.as_slice()), sha512_bytes.get(..48));
    }
}
