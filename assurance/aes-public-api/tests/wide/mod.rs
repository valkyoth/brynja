//! Frozen SP 800-38A F.1.3–F.1.6 first block pairs; no ECB mode API.
use brynja_aes_public_api_fixture::*;

fn hex<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), N * 2);
    let mut result = [0; N];
    for (byte, pair) in result.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        *byte = u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    result
}

macro_rules! cases {
    ($module:ident, $key:ident, $cached:ident, $k:literal, $s:literal, $key_hex:literal, $cipher_hex:literal,
     $public:ident, $cached_public:ident, $decrypt:ident, $cached_decrypt:ident) => {
        mod $module {
            use super::*;
            use aes::{$cached, $key};

            fn key() -> [u8; $k] {
                hex($key_hex)
            }
            fn input() -> [u8; 16] {
                hex("6bc1bee22e409f96e93d7e117393172a")
            }
            fn cipher() -> [u8; 16] {
                hex($cipher_hex)
            }

            #[test]
            fn known_answer_both_directions() {
                let mut storage = [0xa5; $k];
                let mut expanded = [0xa5; $s];
                let owner = $key::new(&key(), &mut storage).unwrap();
                let cached = $cached::new(&key(), &mut expanded).unwrap();
                let mut output = [0x5a; 16];
                assert_eq!(
                    owner.encrypt_block(&input(), &mut output).unwrap().expose(),
                    cipher()
                );
                assert_eq!(output, [0; 16]);
                assert_eq!(
                    owner
                        .decrypt_block(&cipher(), &mut output)
                        .unwrap()
                        .expose(),
                    input()
                );
                assert_eq!(output, [0; 16]);
                assert_eq!(
                    cached
                        .encrypt_block(&input(), &mut output)
                        .unwrap()
                        .expose(),
                    cipher()
                );
                assert_eq!(output, [0; 16]);
                assert_eq!(
                    cached
                        .decrypt_block(&cipher(), &mut output)
                        .unwrap()
                        .expose(),
                    input()
                );
                assert_eq!(output, [0; 16]);
            }

            #[test]
            fn drop_clears_only_owned_regions() {
                let mut keys = [[0xa5; $k]; 3];
                let mut schedules = [[0xa5; $s]; 3];
                let mut outputs = [[0x5a; 16]; 3];
                {
                    let owner = $key::new(&key(), &mut keys[1]).unwrap();
                    let block = owner.encrypt_block(&input(), &mut outputs[1]).unwrap();
                    assert_eq!(block.expose(), cipher());
                }
                assert_eq!(keys, [[0xa5; $k], [0; $k], [0xa5; $k]]);
                assert_eq!(outputs, [[0x5a; 16], [0; 16], [0x5a; 16]]);
                {
                    let cached = $cached::new(&key(), &mut schedules[1]).unwrap();
                    let block = cached.decrypt_block(&cipher(), &mut outputs[1]).unwrap();
                    assert_eq!(block.expose(), input());
                }
                assert_eq!(schedules, [[0xa5; $s], [0; $s], [0xa5; $s]]);
                assert_eq!(outputs, [[0x5a; 16], [0; 16], [0x5a; 16]]);
            }

            #[test]
            fn explicit_clear_and_reuse() {
                let mut storage = [0xa5; $k];
                let mut expanded = [0xa5; $s];
                let mut output = [0x5a; 16];
                for _ in 0..4 {
                    let owner = $key::new(&key(), &mut storage).unwrap();
                    let block = owner.decrypt_block(&cipher(), &mut output).unwrap();
                    assert_eq!(block.expose(), input());
                    block.clear();
                    owner.clear();
                    assert_eq!(output, [0; 16]);
                    assert_eq!(storage, [0; $k]);
                    let cached = $cached::new(&key(), &mut expanded).unwrap();
                    let block = cached.encrypt_block(&input(), &mut output).unwrap();
                    assert_eq!(block.expose(), cipher());
                    block.clear();
                    cached.clear();
                    assert_eq!(output, [0; 16]);
                    assert_eq!(expanded, [0; $s]);
                }
            }

            #[test]
            fn output_outlives_key() {
                let mut storage = [0xa5; $k];
                let mut expanded = [0xa5; $s];
                let mut output = [0x5a; 16];
                let block = $decrypt(&key(), &mut storage, &cipher(), &mut output).unwrap();
                assert_eq!(storage, [0; $k]);
                assert_eq!(block.expose(), input());
                block.clear();
                assert_eq!(output, [0; 16]);
                let block = $cached_decrypt(&key(), &mut expanded, &cipher(), &mut output).unwrap();
                assert_eq!(expanded, [0; $s]);
                assert_eq!(block.expose(), input());
                block.clear();
                assert_eq!(output, [0; 16]);
            }

            #[test]
            fn public_ciphertext_persists_after_key_clear() {
                let input_key = key();
                let mut storage = [0xa5; $k];
                let mut expanded = [0xa5; $s];
                let mut output = [0x5a; 16];
                $public(&input_key, &mut storage, &input(), &mut output).unwrap();
                assert_eq!(output, cipher());
                assert_eq!(storage, [0; $k]);
                output.fill(0x5a);
                $cached_public(&input_key, &mut expanded, &input(), &mut output).unwrap();
                assert_eq!(output, cipher());
                assert_eq!(expanded, [0; $s]);
                assert_eq!(input_key, key());
            }

            #[test]
            fn consumer_unwind_clears_key_and_output() {
                let mut storage = [0xa5; $k];
                let mut expanded = [0xa5; $s];
                let mut output = [0x5a; 16];
                let mut reached = false;
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let owner = $key::new(&key(), &mut storage).unwrap();
                    let block = owner.encrypt_block(&input(), &mut output).unwrap();
                    assert_eq!(block.expose(), cipher());
                    reached = true;
                    panic!("intentional downstream unwind");
                }));
                assert!(result.is_err() && reached);
                assert_eq!(storage, [0; $k]);
                assert_eq!(output, [0; 16]);
                reached = false;
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let cached = $cached::new(&key(), &mut expanded).unwrap();
                    let block = cached.decrypt_block(&cipher(), &mut output).unwrap();
                    assert_eq!(block.expose(), input());
                    reached = true;
                    panic!("intentional downstream cached unwind");
                }));
                assert!(result.is_err() && reached);
                assert_eq!(expanded, [0; $s]);
                assert_eq!(output, [0; 16]);
            }
        }
    };
}

cases!(
    aes192,
    Aes192Key,
    Aes192ExpandedKey,
    24,
    208,
    "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
    "bd334f1d6e45f25ff712a214571fa5cc",
    aes192_public,
    aes192_cached_public,
    aes192_decrypt,
    aes192_cached_decrypt
);
cases!(
    aes256,
    Aes256Key,
    Aes256ExpandedKey,
    32,
    240,
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
    "f3eed1bdb5d2a03c064b5a7e3db181f8",
    aes256_public,
    aes256_cached_public,
    aes256_decrypt,
    aes256_cached_decrypt
);
