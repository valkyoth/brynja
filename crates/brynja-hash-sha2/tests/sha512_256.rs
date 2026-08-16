//! Public SHA-512/256 known-answer, boundary, streaming, and trait acceptance.

use brynja_hash_sha2::{
    FixedOutput, Sha512_256, Sha512_256Digest, Sha512_256Error, Update, sha512, sha512_256,
};

fn expected(text: &str) -> Sha512_256Digest {
    assert_eq!(text.len(), Sha512_256Digest::LENGTH.saturating_mul(2));
    let mut output = [0_u8; Sha512_256Digest::LENGTH];
    for (slot, pair) in output.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        if let [high, low] = pair {
            *slot = nibble(*high)
                .saturating_mul(16)
                .saturating_add(nibble(*low));
        }
    }
    Sha512_256Digest::from_bytes(output)
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
        "97e003903bb971a523ce0c82bda5d6733c76b90deb307559c1bddd35368743f6",
        "563b315214cd5a7ee0bccf937c9776360bc0b9786b707bfbc4fb50576155edbb",
        "bfd5ddd8e43a76faf2ec0c78fc84644f188d6b0ab68c28e5303ff031a223d9f",
        "afb3871e85408af6381e629fae67488068c68398a758f665e2c12258d9ff8ef",
        "fb31ec534b0c40ebffb43390e1e26fcaa28fd68ac24f7e1cafe0fa573103dc1",
        "7058a77edc9b3ea1418b45aa7f5977e126d4861c778ed6332217581eee674d73",
        "9622e63a529f10c11f4a9e3d8feaea848ade0905675f6458ffa132f52749af23",
        "d584438e5"
    ));
    assert_eq!(long.len(), 227);
    let vectors = [
        (
            &b""[..],
            "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
        ),
        (
            &b"\xfa"[..],
            "c4ef36923c64e51e875720e550298a5ab8a3f2f875b1e1a4c9b95babf7344fef",
        ),
        (
            &b"abc"[..],
            "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
        ),
        (
            &long,
            "00ce3b592d4e1a65f780df351fa7b2c01b49df4ea913c3fab24297f5791b18e5",
        ),
    ];
    for (message, digest) in vectors {
        assert_eq!(sha512_256(message), Ok(expected(digest)));
    }
}

#[test]
fn official_nist_cavp_monte_carlo_count_zero_matches() {
    let seed =
        expected("f41ece2613e4573915696b5adcd51ca328be3bf566a9ca99c9ceb0279c1cb0a7").into_bytes();
    let mut previous_3 = seed;
    let mut previous_2 = seed;
    let mut previous_1 = seed;
    for _ in 0..1_000 {
        let mut message = [0_u8; Sha512_256Digest::LENGTH * 3];
        for (part, previous) in message
            .chunks_exact_mut(Sha512_256Digest::LENGTH)
            .zip([previous_3, previous_2, previous_1])
        {
            part.copy_from_slice(&previous);
        }
        let digest = sha512_256(&message)
            .map_or([0; Sha512_256Digest::LENGTH], Sha512_256Digest::into_bytes);
        previous_3 = previous_2;
        previous_2 = previous_1;
        previous_1 = digest;
    }
    assert_eq!(
        Sha512_256Digest::from_bytes(previous_1),
        expected("b1d97a6536896aa01098fb2b9e15d8692621c84077051fc1f70a8a48baa6dfaf")
    );
}

#[test]
fn official_million_a_vector_matches() {
    let repeated = [b'a'; 1_000];
    let mut state = Sha512_256::new();
    for _ in 0..1_000 {
        assert_eq!(state.update(&repeated), Ok(()));
    }
    assert_eq!(
        state.finalize(),
        expected("9a59a052930187a97038cae692f30708aa6491923ef5194394dc68d56c74fb21")
    );
}

#[test]
fn every_padding_boundary_matches_independent_expected_results() {
    let vectors = [
        (
            111,
            "261272bf6a84f95125681f133fe2f8e78045a490f0679844bb9f4e6a2bdb22ee",
        ),
        (
            112,
            "a15a4ba94bf63a05a7a6f318e68896ebcaf200e8b9a9ff023e03cd7c3d633558",
        ),
        (
            127,
            "918524da4ff8041fffb4943b44c4275a444103912abcd3df3ba08400f57352ec",
        ),
        (
            128,
            "a8883fcbaf1bfc9195ad255496e9bf1e522b0e630b5f9117a026f825f0d6097c",
        ),
        (
            129,
            "7f6abab293f8697ae1c1af4e9795e28e4cc397700e382d5ed8bf2c1f9b08ef94",
        ),
        (
            255,
            "e1cf9b5540a1f8813ea8b4212cb974beea3b4a7f67d4bb340b3162054f56d255",
        ),
        (
            256,
            "d9b3a80021c3820faa3bac6eae7e19aff0ed2f8fba8a05117432390bccba3bec",
        ),
        (
            257,
            "aa75f7dcb5ebd41978f16ff28e10aab945bd19bfa2d368d42f423331b0f9d3c7",
        ),
    ];
    for (length, digest) in vectors {
        assert_eq!(
            sha512_256(&patterned(length)),
            Ok(expected(digest)),
            "length {length}"
        );
    }
}

#[test]
fn every_split_and_chunk_width_matches_one_shot() {
    let message = patterned(257);
    let expected_digest = sha512_256(&message);
    assert!(expected_digest.is_ok());
    for split in 0..=message.len() {
        if let (Some(first), Some(second)) = (message.get(..split), message.get(split..)) {
            let mut state = Sha512_256::new();
            assert_eq!(state.update(first), Ok(()));
            assert_eq!(state.update(second), Ok(()));
            assert_eq!(Ok(state.finalize()), expected_digest, "split {split}");
        }
    }
    for width in 1..=message.len() {
        let mut state = Sha512_256::new();
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

    let mut state = Sha512_256::default();
    assert_eq!(state.check_additional_bytes(3), Ok(()));
    assert_eq!(absorb(&mut state, b"abc"), Ok(()));
    assert_eq!(state.message_bytes(), 3);
    assert_eq!(
        finish(state),
        expected("53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23")
    );
    assert_eq!(
        Sha512_256::new().check_additional_bytes(Sha512_256::MAX_MESSAGE_BYTES + 1),
        Err(Sha512_256Error::MessageTooLong)
    );

    let named = sha512_256(b"abc").map(Sha512_256Digest::into_bytes);
    let ordinary = sha512(b"abc").map(|digest| digest.into_bytes());
    assert!(named.is_ok());
    assert!(ordinary.is_ok());
    if let (Ok(named), Ok(ordinary)) = (named, ordinary) {
        assert_ne!(
            Some(named.as_slice()),
            ordinary.get(..Sha512_256Digest::LENGTH)
        );
    }
}
