//! Public SHA-512/224 known-answer, boundary, streaming, and trait acceptance.

use brynja_hash_sha2::{
    FixedOutput, Sha512_224, Sha512_224Digest, Sha512_224Error, Update, sha512, sha512_224,
};

fn expected(text: &str) -> Sha512_224Digest {
    assert_eq!(text.len(), Sha512_224Digest::LENGTH.saturating_mul(2));
    let mut output = [0_u8; Sha512_224Digest::LENGTH];
    for (slot, pair) in output.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        if let [high, low] = pair {
            *slot = nibble(*high)
                .saturating_mul(16)
                .saturating_add(nibble(*low));
        }
    }
    Sha512_224Digest::from_bytes(output)
}

fn decode(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| match pair {
            [high, low] => nibble(*high)
                .saturating_mul(16)
                .saturating_add(nibble(*low)),
            _ => 0,
        })
        .collect()
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
fn official_short_and_long_nist_cavp_vectors_match() {
    let long = decode(concat!(
        "9625ae618ea633fd7ae5b20ceafd6b1f3ab1a6aa20aded66810e78f38925e9c",
        "2fa783a32c40af3f9d7dda0c635b482254b1d85a281af7231109166cd133c836",
        "0e281e5e39bcdd7c601ac47928a8c78cdb3c4f71e97d4d0b1c0ee01dd3db62",
        "f04f44798bb3a76492ba15a91b7110cb5e01babe56589a36fae3a2f336a2d1d",
        "5778dbd23c03ca8db0f25ff0657ff4bca1252adc38c080a5b8f0255ce3be0b",
        "f862823d2ab704729b74e1e275aa305824a566895ed677a460113e2a7bf91f00",
        "d0b8ebc358f3035b27fcc1d3f14a1367cd2769df39a9d21c5ee361f1965cd63",
        "42cc17a1463d6"
    ));
    assert_eq!(long.len(), 227);
    let vectors = [
        (
            &b""[..],
            "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
        ),
        (
            &b"\xcf"[..],
            "4199239e87d47b6feda016802bf367fb6e8b5655eff6225cb2668f4a",
        ),
        (
            &b"abc"[..],
            "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
        ),
        (
            &long,
            "72640a79fbb1cfb26e09b4b35385389ed633a55e092906d01a7186e1",
        ),
    ];
    for (message, digest) in vectors {
        assert_eq!(sha512_224(message), Ok(expected(digest)));
    }
}

#[test]
fn official_nist_cavp_monte_carlo_count_zero_matches() {
    let seed = expected("2e325bf8c98c0be54493d04c329e706343aebe4968fdd33b37da9c0a").into_bytes();
    let mut previous_3 = seed;
    let mut previous_2 = seed;
    let mut previous_1 = seed;
    for _ in 0..1_000 {
        let mut message = [0_u8; Sha512_224Digest::LENGTH * 3];
        for (part, previous) in message
            .chunks_exact_mut(Sha512_224Digest::LENGTH)
            .zip([previous_3, previous_2, previous_1])
        {
            part.copy_from_slice(&previous);
        }
        let digest = sha512_224(&message)
            .map_or([0; Sha512_224Digest::LENGTH], Sha512_224Digest::into_bytes);
        previous_3 = previous_2;
        previous_2 = previous_1;
        previous_1 = digest;
    }
    assert_eq!(
        Sha512_224Digest::from_bytes(previous_1),
        expected("9ee006873962aa0842d636c759646a4ef4b65bcbebcc35430b20f7f4")
    );
}

#[test]
fn official_million_a_vector_matches() {
    let repeated = [b'a'; 1_000];
    let mut state = Sha512_224::new();
    for _ in 0..1_000 {
        assert_eq!(state.update(&repeated), Ok(()));
    }
    assert_eq!(
        state.finalize(),
        expected("37ab331d76f0d36de422bd0edeb22a28accd487b7a8453ae965dd287")
    );
}

#[test]
fn every_padding_boundary_matches_independent_expected_results() {
    let vectors = [
        (
            111,
            "fd146f91b7cac1558fab20649c3be9c7b74bb95d87d98506a5b19329",
        ),
        (
            112,
            "9e5c400bd74d366df313e0202c3df94174ab775008378b49061cc7d2",
        ),
        (
            127,
            "d303f24c91299201196871912020f9b82eb7103d926d9a498ded207f",
        ),
        (
            128,
            "fc1772084d1c2ff1357e8b9432524c32389be6dac08e126f4c044d78",
        ),
        (
            129,
            "cd26cf72e089785f5196d56261eea9ec4e8cb4374905b8897e8bc93c",
        ),
        (
            255,
            "0c68217a873bff2fef2821661efa08e6b9c603237ab796a4a4407bc4",
        ),
        (
            256,
            "0373a9546477b1edea390dfda00d407b3b9bf82906bbb6e9ab2d5671",
        ),
        (
            257,
            "accdcbfddf4687cde9067e56794d53613a1c3aa305f91b5ba6fc1cca",
        ),
    ];
    for (length, digest) in vectors {
        assert_eq!(
            sha512_224(&patterned(length)),
            Ok(expected(digest)),
            "length {length}"
        );
    }
}

#[test]
fn every_split_and_chunk_width_matches_one_shot() {
    let message = patterned(257);
    let expected_digest = sha512_224(&message);
    assert!(expected_digest.is_ok());
    for split in 0..=message.len() {
        if let (Some(first), Some(second)) = (message.get(..split), message.get(split..)) {
            let mut state = Sha512_224::new();
            assert_eq!(state.update(first), Ok(()));
            assert_eq!(state.update(second), Ok(()));
            assert_eq!(Ok(state.finalize()), expected_digest, "split {split}");
        }
    }
    for width in 1..=message.len() {
        let mut state = Sha512_224::new();
        for chunk in message.chunks(width) {
            assert_eq!(state.update(chunk), Ok(()));
        }
        assert_eq!(Ok(state.finalize()), expected_digest, "width {width}");
    }
}

#[test]
fn trait_api_length_domain_and_algorithm_identity_are_exact() {
    fn absorb<T: Update>(state: &mut T, input: &[u8]) -> Result<(), T::Error> {
        state.update(input)
    }
    fn finish<T: FixedOutput>(state: T) -> T::Output {
        state.finalize()
    }

    let mut state = Sha512_224::default();
    assert_eq!(state.check_additional_bytes(3), Ok(()));
    assert_eq!(absorb(&mut state, b"abc"), Ok(()));
    assert_eq!(state.message_bytes(), 3);
    assert_eq!(
        finish(state),
        expected("4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa")
    );
    assert_eq!(
        Sha512_224::new().check_additional_bytes(Sha512_224::MAX_MESSAGE_BYTES + 1),
        Err(Sha512_224Error::MessageTooLong)
    );

    let named = sha512_224(b"abc").map(Sha512_224Digest::into_bytes);
    let ordinary = sha512(b"abc").map(|digest| digest.into_bytes());
    assert!(named.is_ok());
    assert!(ordinary.is_ok());
    if let (Ok(named), Ok(ordinary)) = (named, ordinary) {
        assert_ne!(
            Some(named.as_slice()),
            ordinary.get(..Sha512_224Digest::LENGTH)
        );
    }
}
