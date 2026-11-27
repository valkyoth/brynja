use super::*;

macro_rules! faults {
    ($module:ident, $key:ident, $cached:ident, $k:literal, $s:literal, $rounds:literal, $mask:literal) => {
        mod $module {
            use super::*;
            #[test]
            fn every_round_error_and_unwind_is_transactional() {
                for inverse in [false, true] {
                    for unwind in [false, true] {
                        for point in 0..=$rounds {
                            let mut storage = [0; $k];
                            let mut expanded = [0; $s];
                            let key = $key::new(&[0x42; $k], &mut storage).unwrap();
                            let cached = $cached::new(&[0x42; $k], &mut expanded).unwrap();
                            for cache in [false, true] {
                                let mut out = [0xa5; 16];
                                POINT.set(0);
                                FAIL.set(Some((point, unwind)));
                                CLEARED.set(0);
                                let result = catch_unwind(AssertUnwindSafe(|| {
                                    let block = match (cache, inverse) {
                                        (false, false) => key.encrypt_block(&[0x77; 16], &mut out),
                                        (false, true) => key.decrypt_block(&[0x77; 16], &mut out),
                                        (true, false) => {
                                            cached.encrypt_block(&[0x77; 16], &mut out)
                                        }
                                        (true, true) => cached.decrypt_block(&[0x77; 16], &mut out),
                                    };
                                    block.map(|b| b.clear())
                                }));
                                FAIL.set(None);
                                if unwind {
                                    assert!(result.is_err());
                                } else {
                                    assert!(matches!(result, Ok(Err(Error::SecretMemory))));
                                }
                                assert_eq!(out, [0; 16]);
                                assert_eq!(CLEARED.get(), if cache { 2 } else { $mask | 6 });
                                // Operation failure does not destroy a reusable software key.
                                key.encrypt_block(&[0; 16], &mut out).unwrap().clear();
                                cached.encrypt_block(&[0; 16], &mut out).unwrap().clear();
                            }
                        }
                    }
                }
            }
            #[test]
            fn every_public_round_failure_preserves_output() {
                for unwind in [false, true] {
                    for point in 0..=$rounds {
                        let mut storage = [0; $k];
                        let mut expanded = [0; $s];
                        let key = $key::new(&[0x42; $k], &mut storage).unwrap();
                        let cached = $cached::new(&[0x42; $k], &mut expanded).unwrap();
                        for cache in [false, true] {
                            let mut out = [0xa5; 16];
                            POINT.set(0);
                            FAIL.set(Some((point, unwind)));
                            CLEARED.set(0);
                            let result = catch_unwind(AssertUnwindSafe(|| {
                                if cache {
                                    cached.encrypt_block_public(
                                        &[0; 16],
                                        &mut out,
                                        PublicCiphertext::acknowledge(),
                                    )
                                } else {
                                    key.encrypt_block_public(
                                        &[0; 16],
                                        &mut out,
                                        PublicCiphertext::acknowledge(),
                                    )
                                }
                            }));
                            FAIL.set(None);
                            if unwind {
                                assert!(result.is_err());
                            } else {
                                assert!(matches!(result, Ok(Err(Error::SecretMemory))));
                            }
                            assert_eq!(out, [0xa5; 16]);
                            assert_eq!(CLEARED.get(), if cache { 2 } else { $mask | 6 });
                        }
                    }
                }
            }
            #[test]
            fn every_expansion_failure_clears_admitted_storage() {
                // Initial key copy + every generated word + final populated import.
                let expansion_points = 1 + ($s - $k) / 4;
                for unwind in [false, true] {
                    for point in 0..=expansion_points {
                        let input = [0x42; $k];
                        let mut storage = [[0xa5; $s]; 3];
                        EXPANSION_POINT.set(0);
                        EXPANSION_FAIL.set(Some((point, unwind)));
                        CLEARED.set(0);
                        let result = catch_unwind(AssertUnwindSafe(|| {
                            $cached::new(&input, &mut storage[1]).map(|k| k.clear())
                        }));
                        EXPANSION_FAIL.set(None);
                        if unwind {
                            assert!(result.is_err());
                        } else {
                            assert!(matches!(result, Ok(Err(Error::SecretMemory))));
                        }
                        assert_eq!(storage, [[0xa5; $s], [0; $s], [0xa5; $s]]);
                        assert_eq!(CLEARED.get(), $mask | 4);
                        assert_eq!(input, [0x42; $k]);
                    }
                    for point in 0..expansion_points {
                        let mut storage = [0; $k];
                        let key = $key::new(&[0x42; $k], &mut storage).unwrap();
                        for operation in 0..3 {
                            let mut out = [0xa5; 16];
                            EXPANSION_POINT.set(0);
                            EXPANSION_FAIL.set(Some((point, unwind)));
                            CLEARED.set(0);
                            let result = catch_unwind(AssertUnwindSafe(|| {
                                if operation == 2 {
                                    key.encrypt_block_public(
                                        &[0; 16],
                                        &mut out,
                                        PublicCiphertext::acknowledge(),
                                    )
                                } else if operation == 0 {
                                    key.encrypt_block(&[0; 16], &mut out).map(|b| b.clear())
                                } else {
                                    key.decrypt_block(&[0; 16], &mut out).map(|b| b.clear())
                                }
                            }));
                            EXPANSION_FAIL.set(None);
                            if unwind {
                                assert!(result.is_err());
                            } else {
                                assert!(matches!(result, Ok(Err(Error::SecretMemory))));
                            }
                            assert_eq!(out, if operation == 2 { [0xa5; 16] } else { [0; 16] });
                            assert_eq!(CLEARED.get(), $mask | 4);
                        }
                    }
                }
            }
            #[test]
            fn cached_operations_do_not_expand_again() {
                let mut storage = [0; $s];
                let cached = $cached::new(&[0x42; $k], &mut storage).unwrap();
                let mut out = [0; 16];
                EXPANSION_POINT.set(0);
                EXPANSION_FAIL.set(Some((0, true)));
                cached.encrypt_block(&[0; 16], &mut out).unwrap().clear();
                cached.decrypt_block(&[0; 16], &mut out).unwrap().clear();
                cached
                    .encrypt_block_public(&[0; 16], &mut out, PublicCiphertext::acknowledge())
                    .unwrap();
                EXPANSION_FAIL.set(None);
                assert_eq!(EXPANSION_POINT.get(), 0);
                cached.clear();
                assert_eq!(storage, [0; $s]);
            }
        }
    };
}

faults!(aes192, Aes192Key, Aes192ExpandedKey, 24, 208, 12, 8);
faults!(aes256, Aes256Key, Aes256ExpandedKey, 32, 240, 14, 16);

// Complete key expansions from the pinned FIPS 197-upd1 Appendix A.2/A.3.
fn schedule<const K: usize, const S: usize, const R: usize>(words: &str) -> Result<(), Error> {
    let expected: std::vec::Vec<u8> = words
        .split_whitespace()
        .map(|word| u32::from_str_radix(word, 16).map(u32::to_be_bytes))
        .collect::<Result<std::vec::Vec<_>, _>>()
        .map_err(|_| Error::SecretMemory)?
        .into_iter()
        .flatten()
        .collect();
    assert_eq!(expected.len(), S);
    let mut actual = Scratch::<S>::new();
    portable::wide::expand::<K, S, R>(
        expected.get(..K).ok_or(Error::SecretMemory)?,
        &mut actual.0,
    )?;
    assert_eq!(actual.0.as_slice(), expected);
    Ok(())
}

#[test]
fn fips197_complete_aes192_schedule() -> Result<(), Error> {
    schedule::<24, 208, 12>(
        "8e73b0f7 da0e6452 c810f32b 809079e5 62f8ead2 522c6b7b
        fe0c91f7 2402f5a5 ec12068e 6c827f6b 0e7a95b9 5c56fec2
        4db7b4bd 69b54118 85a74796 e92538fd e75fad44 bb095386
        485af057 21efb14f a448f6d9 4d6dce24 aa326360 113b30e6
        a25e7ed5 83b1cf9a 27f93943 6a94f767 c0a69407 d19da4e1
        ec1786eb 6fa64971 485f7032 22cb8755 e26d1352 33f0b7b3
        40beeb28 2f18a259 6747d26b 458c553e a7e1466c 9411f1df
        821f750a ad07d753 ca400538 8fcc5006 282d166a bc3ce7b5
        e98ba06f 448c773c 8ecc7204 01002202",
    )
}

#[test]
fn fips197_complete_aes256_schedule() -> Result<(), Error> {
    schedule::<32, 240, 14>(
        "603deb10 15ca71be 2b73aef0 857d7781 1f352c07 3b6108d7 2d9810a3 0914dff4
        9ba35411 8e6925af a51a8b5f 2067fcde a8b09c1a 93d194cd be49846e b75d5b9a
        d59aecb8 5bf3c917 fee94248 de8ebe96 b5a9328a 2678a647 98312229 2f6c79b3
        812c81ad dadf48ba 24360af2 fab8b464 98c5bfc9 bebd198e 268c3ba7 09e04214
        68007bac b2df3316 96e939e4 6c518d80 c814e204 76a9fb8a 5025c02d 59c58239
        de136967 6ccc5a71 fa256395 9674ee15 5886ca5d 2e2f31d7 7e0af1fa 27cf73c3
        749c47ab 18501dda e2757e4f 7401905a cafaaae3 e4d59b34 9adf6ace bd10190d
        fe4890d1 e6188d0b 046df344 706c631e",
    )
}
