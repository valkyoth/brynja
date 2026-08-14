//! Public SHA-256 vectors, boundaries, and consumer behavior.

use brynja_hash_sha2::{Sha256, Sha256Digest, sha256};

#[test]
fn official_fips_vectors() {
    check(
        b"",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
    check(
        b"abc",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    check(
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    );

    let repeated = [b'a'; 1_000];
    let mut state = Sha256::new();
    for _ in 0..1_000 {
        assert_eq!(state.update(&repeated), Ok(()));
    }
    assert_eq!(
        state.finalize(),
        expected("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
    );
}

#[test]
fn padding_boundaries_have_exact_digests() {
    let mut message = [0_u8; 65];
    for (index, byte) in message.iter_mut().enumerate() {
        if let Ok(value) = u8::try_from(index) {
            *byte = value;
        }
    }
    for (length, digest) in [
        (
            55,
            "463eb28e72f82e0a96c0a4cc53690c571281131f672aa229e0d45ae59b598b59",
        ),
        (
            56,
            "da2ae4d6b36748f2a318f23e7ab1dfdf45acdc9d049bd80e59de82a60895f562",
        ),
        (
            63,
            "29af2686fd53374a36b0846694cc342177e428d1647515f078784d69cdb9e488",
        ),
        (
            64,
            "fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108",
        ),
        (
            65,
            "4bfd2c8b6f1eec7a2afeb48b934ee4b2694182027e6d0fc075074f2fabb31781",
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
    let mut message = [0_u8; 1_025];
    let mut generated = 0x9e37_79b9_u32;
    for byte in &mut message {
        generated = generated
            .wrapping_mul(1_664_525)
            .wrapping_add(1_013_904_223);
        let [_, _, _, last] = generated.to_be_bytes();
        *byte = last;
    }
    let one_shot = sha256(&message);
    assert!(one_shot.is_ok());
    for chunk_size in 1..=80 {
        let mut state = Sha256::new();
        assert_eq!(state.update(&[]), Ok(()));
        for chunk in message.chunks(chunk_size) {
            assert_eq!(state.update(chunk), Ok(()));
            assert_eq!(state.update(&[]), Ok(()));
        }
        assert_eq!(Ok(state.finalize()), one_shot);
    }
}

#[test]
fn downstream_style_real_content_uses_only_public_api() {
    let content = b"Brynja public SHA-256 consumer acceptance\n";
    let digest = sha256(content);
    assert_eq!(
        digest,
        Ok(expected(
            "c9be0da9b7d6b7de699ef2e31e5c656b738b0aa7c15e280655a1ad704ed8f045"
        ))
    );

    let mut streamed = Sha256::new();
    for chunk in content.chunks(7) {
        assert_eq!(streamed.update(chunk), Ok(()));
    }
    assert_eq!(Ok(streamed.finalize()), digest);
}

fn check(input: &[u8], digest: &str) {
    assert_eq!(sha256(input), Ok(expected(digest)));
}

fn expected(hex: &str) -> Sha256Digest {
    let mut bytes = [0_u8; Sha256Digest::LENGTH];
    for (target, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        if let [high, low] = pair {
            *target = nibble(*high)
                .saturating_mul(16)
                .saturating_add(nibble(*low));
        }
    }
    Sha256Digest::from_bytes(bytes)
}

const fn nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte.saturating_sub(b'0'),
        b'a'..=b'f' => byte.saturating_sub(b'a').saturating_add(10),
        _ => 0,
    }
}
