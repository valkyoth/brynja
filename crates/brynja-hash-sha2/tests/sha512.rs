//! Public SHA-512 known-answer, boundary, streaming, and trait acceptance.

use brynja_hash_sha2::{FixedOutput, Sha512, Sha512Digest, Sha512Error, Update, sha512};

const LONG_MESSAGE: &[u8] = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

fn expected(text: &str) -> Sha512Digest {
    assert_eq!(text.len(), Sha512Digest::LENGTH.saturating_mul(2));
    let mut output = [0_u8; Sha512Digest::LENGTH];
    for (slot, pair) in output.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        if let [high, low] = pair {
            *slot = nibble(*high)
                .saturating_mul(16)
                .saturating_add(nibble(*low));
        }
    }
    Sha512Digest::from_bytes(output)
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
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        ),
        (
            &b"abc"[..],
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ),
        (
            LONG_MESSAGE,
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
        ),
        (
            &[0x21][..],
            "3831a6a6155e509dee59a7f451eb35324d8f8f2df6e3708894740f98fdee23889f4de5adb0c5010dfb555cda77c8ab5dc902094c52de3278f35a75ebc25f093a",
        ),
    ];
    for (message, digest) in vectors {
        assert_eq!(sha512(message), Ok(expected(digest)));
    }
}

#[test]
fn official_million_a_vector_matches() {
    let repeated = [b'a'; 1_000];
    let mut state = Sha512::new();
    for _ in 0..1_000 {
        assert_eq!(state.update(&repeated), Ok(()));
    }
    assert_eq!(
        state.finalize(),
        expected(
            "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
        )
    );
}

#[test]
fn official_nist_cavp_monte_carlo_count_zero_matches() {
    let seed = expected(
        "5c337de5caf35d18ed90b5cddfce001ca1b8ee8602f367e7c24ccca6f893802fb1aca7a3dae32dcd60800a59959bc540d63237876b799229ae71a2526fbc52cd",
    )
    .into_bytes();
    let mut previous_3 = seed;
    let mut previous_2 = seed;
    let mut previous_1 = seed;
    for _ in 0..1_000 {
        let mut message = [0_u8; Sha512Digest::LENGTH * 3];
        for (part, previous) in message
            .chunks_exact_mut(Sha512Digest::LENGTH)
            .zip([previous_3, previous_2, previous_1])
        {
            part.copy_from_slice(&previous);
        }
        let digest = sha512(&message).map_or([0; Sha512Digest::LENGTH], Sha512Digest::into_bytes);
        previous_3 = previous_2;
        previous_2 = previous_1;
        previous_1 = digest;
    }
    assert_eq!(
        Sha512Digest::from_bytes(previous_1),
        expected(
            "ada69add0071b794463c8806a177326735fa624b68ab7bcab2388b9276c036e4eaaff87333e83c81c0bca0359d4aeebcbcfd314c0630e0c2af68c1fb19cc470e"
        )
    );
}

#[test]
fn every_padding_boundary_matches_independent_expected_results() {
    let vectors = [
        (
            111,
            "6af871e462c926226513e349fa78a9e0f883fdd8596a6825016181db3f2f00eb4259d4ec6a142f109649f693a060969de17785b80ccb11339d0e7fc7f4338f9d",
        ),
        (
            112,
            "2ee972137398251bb0daa44091e6952666257fd7eb4faf78adb4a517e0566915d24e5db3262460bd251b2a007af178cfa614769d77188577667ce70f4f34c9f7",
        ),
        (
            127,
            "27e3c653f1f3714618de9cfef7ac8522ab5ad53be8e7263b7ff2f2220f75acb663fa139f1393a44a507931a500ed8590daa9cdd85e0a6a44977f788e655259d7",
        ),
        (
            128,
            "4a9fd9104582db08e0d093df8dc89ee5384879480b2ffa501ce613ffbcb6896a7b51c892a96149443532e753729fbb0a47133d68f8f4e3effe626b632d9cbf47",
        ),
        (
            129,
            "19e20c253ec2cd56a60882718842dafa9893a22fc794f80d4f1153103abf401691ddfce59710b1d049b4d8c6b0667aee8dc8d7221fb05af3b905939ebf3a0ecd",
        ),
        (
            255,
            "d1cd9fab2c2907faad2a8cded481712475d0de0657d824b7ae0dd480b49327e8604624a2e7db636ec67c3f61517bd283c229b252db729ea3fff9057ea7ffd6c3",
        ),
        (
            256,
            "3921103f59c486e41151d793b70bc925f9fbd02788897a67418f35bb18b568e55e04d50a1984b471de348a0304bae50604c70278723f3ac9ffea202ecc3062fd",
        ),
        (
            257,
            "c663e642bbf2eb3d6f7c58a3d7814e70e93ffb18efd0859b79982342a276bcc2881c383534ad9877ec8f7b401fd6da4ebaf5ec9daa09afe534701fcff606b34e",
        ),
    ];
    for (length, digest) in vectors {
        assert_eq!(
            sha512(&patterned(length)),
            Ok(expected(digest)),
            "length {length}"
        );
    }
}

#[test]
fn every_two_part_split_and_fixed_chunk_width_matches_one_shot() {
    let message = patterned(257);
    let expected_digest = sha512(&message);
    assert!(expected_digest.is_ok());
    for split in 0..=message.len() {
        if let (Some(first), Some(second)) = (message.get(..split), message.get(split..)) {
            let mut state = Sha512::new();
            assert_eq!(state.update(first), Ok(()));
            assert_eq!(state.update(second), Ok(()));
            assert_eq!(Ok(state.finalize()), expected_digest, "split {split}");
        }
    }
    for width in 1..=message.len() {
        let mut state = Sha512::new();
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

    let content = b"Brynja public SHA-512 consumer acceptance\n";
    let mut state = Sha512::default();
    assert_eq!(state.check_additional_bytes(content.len() as u128), Ok(()));
    assert!(absorb(&mut state, content).is_ok());
    assert_eq!(state.message_bytes(), content.len() as u128);
    assert_eq!(
        finish(state),
        expected(
            "08d118ee0bbec868c3df47f652f0a01a233f4e4ad9b6a4d5611a033d5e485f3b64d869ca681df85f62339fac26cb57b0b5d0169d705e4ff07a50246942135486"
        )
    );

    assert_eq!(
        Sha512::new().check_additional_bytes(Sha512::MAX_MESSAGE_BYTES),
        Ok(())
    );
    assert_eq!(
        Sha512::new().check_additional_bytes(Sha512::MAX_MESSAGE_BYTES + 1),
        Err(Sha512Error::MessageTooLong)
    );
}
