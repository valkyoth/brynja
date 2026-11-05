//! Public AES-192/256 owners. SP 800-38A F.1.3–F.1.6 block examples only;
//! no ECB mode API or CAVP validation is claimed.
use brynja_crypto::aes::*;

fn hex<const N: usize>(text: &str) -> Result<[u8; N], Error> {
    assert_eq!(Some(text.len()), N.checked_mul(2));
    let mut result = [0; N];
    for (byte, pair) in result.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        *byte = match core::str::from_utf8(pair)
            .ok()
            .and_then(|s| u8::from_str_radix(s, 16).ok())
        {
            Some(value) => value,
            None => return Err(Error::SecretMemory),
        };
    }
    Ok(result)
}

const PLAINTEXT: [&str; 4] = [
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
];

macro_rules! cases {
    ($module:ident, $key:ident, $cached:ident, $k:literal, $s:literal, $input_key:literal, $cipher:expr) => {
        mod $module {
            use super::*;
            #[test]
            fn official_blocks_all_owners_and_directions() {
                let input_key = hex::<$k>($input_key).unwrap();
                let mut storage = [0xa5; $k];
                let key = $key::new(&input_key, &mut storage).unwrap();
                let mut expanded = [0xa5; $s];
                let cached = $cached::new(&input_key, &mut expanded).unwrap();
                for (input, ciphertext) in PLAINTEXT.into_iter().zip($cipher) {
                    let input = hex::<16>(input).unwrap();
                    let expected = hex::<16>(ciphertext).unwrap();
                    let mut output = [0x55; 16];
                    assert_eq!(
                        key.encrypt_block(&input, &mut output).unwrap().expose(),
                        expected
                    );
                    assert_eq!(output, [0; 16]);
                    assert_eq!(
                        key.decrypt_block(&expected, &mut output).unwrap().expose(),
                        input
                    );
                    assert_eq!(output, [0; 16]);
                    assert_eq!(
                        cached.encrypt_block(&input, &mut output).unwrap().expose(),
                        expected
                    );
                    assert_eq!(output, [0; 16]);
                    assert_eq!(
                        cached
                            .decrypt_block(&expected, &mut output)
                            .unwrap()
                            .expose(),
                        input
                    );
                    assert_eq!(output, [0; 16]);
                    key.encrypt_block_public(&input, &mut output, PublicCiphertext::acknowledge())
                        .unwrap();
                    assert_eq!(output, expected);
                    output.fill(0xa5);
                    cached
                        .encrypt_block_public(&input, &mut output, PublicCiphertext::acknowledge())
                        .unwrap();
                    assert_eq!(output, expected);
                }
                key.clear();
                cached.clear();
                assert_eq!(storage, [0; $k]);
                assert_eq!(expanded, [0; $s]);
                assert_eq!(input_key, hex::<$k>($input_key).unwrap());
            }
            #[test]
            fn drop_clears_exact_regions_and_preserves_canaries() {
                let mut storage = [[0xa5; $k]; 3];
                let mut expanded = [[0xa5; $s]; 3];
                let mut output = [[0x55; 16]; 3];
                {
                    let key = $key::new(&[0; $k], &mut storage[1]).unwrap();
                    key.encrypt_block(&[0; 16], &mut output[1]).unwrap().clear();
                    let cached = $cached::new(&[0; $k], &mut expanded[1]).unwrap();
                    let block = cached.decrypt_block(&[0xff; 16], &mut output[1]).unwrap();
                    assert_eq!(block.expose().len(), 16);
                }
                assert_eq!(storage, [[0xa5; $k], [0; $k], [0xa5; $k]]);
                assert_eq!(expanded, [[0xa5; $s], [0; $s], [0xa5; $s]]);
                assert_eq!(output, [[0x55; 16], [0; 16], [0x55; 16]]);
            }
            #[test]
            fn output_outlives_both_key_owners() {
                let mut storage = [0; $k];
                let mut expanded = [0; $s];
                let mut output = [0; 16];
                let block = {
                    let key = $key::new(&[0x42; $k], &mut storage).unwrap();
                    key.encrypt_block(&[0; 16], &mut output).unwrap()
                };
                assert_eq!(storage, [0; $k]);
                let expected: [u8; 16] = block.expose().try_into().unwrap();
                block.clear();
                assert_eq!(output, [0; 16]);
                let block = {
                    let key = $cached::new(&[0x42; $k], &mut expanded).unwrap();
                    key.encrypt_block(&[0; 16], &mut output).unwrap()
                };
                assert_eq!(expanded, [0; $s]);
                assert_eq!(block.expose(), expected);
                block.clear();
                assert_eq!(output, [0; 16]);
            }
            #[test]
            fn clearing_storage_allows_fresh_import_and_reuse() {
                let mut storage = [0; $k];
                let mut expanded = [0; $s];
                let mut out = [0; 16];
                for byte in [0, 1, 0x80, 0xff] {
                    let key = $key::new(&[byte; $k], &mut storage).unwrap();
                    let cached = $cached::new(&[byte; $k], &mut expanded).unwrap();
                    let mut ciphertext = [0; 16];
                    for input in [[0; 16], [0xff; 16], [0x80; 16]] {
                        key.encrypt_block_public(
                            &input,
                            &mut ciphertext,
                            PublicCiphertext::acknowledge(),
                        )
                        .unwrap();
                        assert_eq!(
                            cached
                                .decrypt_block(&ciphertext, &mut out)
                                .unwrap()
                                .expose(),
                            input
                        );
                        cached
                            .encrypt_block_public(
                                &input,
                                &mut ciphertext,
                                PublicCiphertext::acknowledge(),
                            )
                            .unwrap();
                        assert_eq!(
                            key.decrypt_block(&ciphertext, &mut out).unwrap().expose(),
                            input
                        );
                    }
                    key.clear();
                    cached.clear();
                    assert_eq!(storage, [0; $k]);
                    assert_eq!(expanded, [0; $s]);
                    assert_eq!(out, [0; 16]);
                }
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
    [
        "bd334f1d6e45f25ff712a214571fa5cc",
        "974104846d0ad3ad7734ecb3ecee4eef",
        "ef7afd2270e2e60adce0ba2face6444e",
        "9a4b41ba738d6c72fb16691603c18e0e"
    ]
);
cases!(
    aes256,
    Aes256Key,
    Aes256ExpandedKey,
    32,
    240,
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
    [
        "f3eed1bdb5d2a03c064b5a7e3db181f8",
        "591ccb10d410ed26dc5ba74a31362870",
        "b6ed21b99ca6f4f9f153e7b1beafed1d",
        "23304b7a39f9f3ff067d8d8f9e24ecc7"
    ]
);
