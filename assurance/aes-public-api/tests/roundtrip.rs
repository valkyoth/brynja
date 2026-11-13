//! Composition checks complement, but never replace, the frozen known answers.
use brynja_aes_public_api_fixture::aes;

macro_rules! round_trip {
    ($name:ident, $key:ident, $cached:ident, $k:literal, $s:literal) => {
        #[test]
        fn $name() {
            // Public deterministic fixtures, not generated cryptographic keys.
            for seed in [0u8, 1, 0x55, 0xaa, 0xfe, 0xff] {
                let input_key: [u8; $k] = core::array::from_fn(|i| seed.wrapping_add(i as u8));
                let input: [u8; 16] = core::array::from_fn(|i| seed ^ (i as u8).wrapping_mul(17));
                for cached_encrypt in [false, true] {
                    for cached_decrypt in [false, true] {
                        let mut key_storage = [[0xa5; $k]; 3];
                        let mut schedule_storage = [[0x5a; $s]; 3];
                        let mut ciphertext = [[0x3c; 16]; 3];
                        let mut plaintext = [[0xc3; 16]; 3];
                        let encrypted = if cached_encrypt {
                            let owner =
                                aes::$cached::new(&input_key, &mut schedule_storage[1]).unwrap();
                            let block = owner.encrypt_block(&input, &mut ciphertext[1]).unwrap();
                            owner.clear();
                            block
                        } else {
                            let owner = aes::$key::new(&input_key, &mut key_storage[1]).unwrap();
                            let block = owner.encrypt_block(&input, &mut ciphertext[1]).unwrap();
                            owner.clear();
                            block
                        };
                        // Decrypt the actual encryption result, across owner forms,
                        // after the encrypting key/schedule has already been cleared.
                        // Convert the borrowed exposure to a fixed-width reference;
                        // this creates no unowned copy of the secret block.
                        let encrypted_input: &[u8; 16] = encrypted.expose().try_into().unwrap();
                        let decrypted = if cached_decrypt {
                            let owner =
                                aes::$cached::new(&input_key, &mut schedule_storage[1]).unwrap();
                            let block = owner
                                .decrypt_block(encrypted_input, &mut plaintext[1])
                                .unwrap();
                            owner.clear();
                            block
                        } else {
                            let owner = aes::$key::new(&input_key, &mut key_storage[1]).unwrap();
                            let block = owner
                                .decrypt_block(encrypted_input, &mut plaintext[1])
                                .unwrap();
                            owner.clear();
                            block
                        };
                        assert_eq!(decrypted.expose(), input);
                        decrypted.clear();
                        encrypted.clear();
                        assert_eq!(ciphertext, [[0x3c; 16], [0; 16], [0x3c; 16]]);
                        assert_eq!(plaintext, [[0xc3; 16], [0; 16], [0xc3; 16]]);
                        let expected_key = if cached_encrypt && cached_decrypt {
                            [0xa5; $k]
                        } else {
                            [0; $k]
                        };
                        let expected_schedule = if cached_encrypt || cached_decrypt {
                            [0; $s]
                        } else {
                            [0x5a; $s]
                        };
                        assert_eq!(key_storage, [[0xa5; $k], expected_key, [0xa5; $k]]);
                        assert_eq!(
                            schedule_storage,
                            [[0x5a; $s], expected_schedule, [0x5a; $s]]
                        );
                        assert_eq!(
                            input_key,
                            core::array::from_fn(|i| seed.wrapping_add(i as u8))
                        );
                        assert_eq!(
                            input,
                            core::array::from_fn(|i| seed ^ (i as u8).wrapping_mul(17))
                        );
                    }
                }
            }
        }
    };
}

round_trip!(aes128, Aes128Key, Aes128ExpandedKey, 16, 176);
round_trip!(aes192, Aes192Key, Aes192ExpandedKey, 24, 208);
round_trip!(aes256, Aes256Key, Aes256ExpandedKey, 32, 240);
