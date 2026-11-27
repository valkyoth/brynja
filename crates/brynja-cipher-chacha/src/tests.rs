//! Standalone known answers included in the crate archive.
extern crate std;
mod appendix;

macro_rules! check_owner {
    ($owner:ident) => {{
        let mut covered_group = false;
        for (key, nonce, first, input, expected) in appendix::VECTORS {
            let mut stream = $owner::new(key, *nonce, first);
            let mut data = std::vec![0xa5; input.len()];
            let before = stream.remaining_bytes();
            assert_eq!(stream.apply_keystream(input, &mut data), Ok(()));
            assert_eq!(data, expected);
            assert_eq!(before.checked_sub(stream.remaining_bytes()), Some(input.len() as u64));
            let mut decrypt = $owner::new(key, *nonce, first);
            assert_eq!(decrypt.apply_keystream_in_place(&mut data), Ok(()));
            assert_eq!(data, input);
            covered_group |= input.len() >= 256;
        }
        assert!(covered_group);
    }};
}

#[test]
fn portable_rfc8439() {
    use crate::chacha20::ChaCha20;
    check_owner!(ChaCha20);
}

#[test]
#[cfg(all(
    feature = "chacha20-sse2",
    target_arch = "x86_64",
    target_feature = "sse2"
))]
fn sse2_rfc8439() {
    use crate::ChaCha20Sse2;
    check_owner!(ChaCha20Sse2);
}

#[test]
#[cfg(all(
    feature = "chacha20-neon",
    target_arch = "aarch64",
    target_feature = "neon",
    target_endian = "little"
))]
fn neon_rfc8439() {
    use crate::ChaCha20Neon;
    check_owner!(ChaCha20Neon);
}
