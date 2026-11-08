//! Public-owner lifecycle observations, not internal AES fault injection.
#![forbid(unsafe_code)]

use brynja_aes_public_api_fixture::aes::*;
use std::hint::black_box;

fn hex<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), N * 2);
    let mut result = [0; N];
    for (byte, pair) in result.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    result
}

fn guarded<const N: usize>(bytes: &[[u8; N]; 3], middle: &[u8; N]) {
    assert_eq!(black_box(&bytes[0]), &[0xa5; N]);
    assert_eq!(black_box(&bytes[1]), middle);
    assert_eq!(black_box(&bytes[2]), &[0xa5; N]);
}

fn caller_result(action: impl FnOnce() -> Result<(), &'static str>) -> Result<(), &'static str> {
    action()
}

#[cfg(panic = "unwind")]
#[derive(Debug, PartialEq)]
struct CallerPanic;

#[cfg(panic = "unwind")]
fn unwind(action: impl FnOnce()) {
    // resume_unwind avoids changing the process panic hook. An assertion panic
    // is not the expected payload and must never be counted as a successful test.
    let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(action))
        .expect_err("caller unwind did not occur");
    assert!(payload.is::<CallerPanic>(), "unexpected panic payload");
}

#[cfg(panic = "unwind")]
fn caller_panic() -> ! {
    std::panic::resume_unwind(Box::new(CallerPanic));
}

macro_rules! owner_cases {
    ($name:ident, $boundary:ident, $owner:ident, $k:literal, $s:literal, $expected:literal) => {
        // An opaque caller callback may unwind while both real public owners
        // are live. Keep this consumer-only boundary visible after fat LTO.
        #[inline(never)]
        fn $boundary(owner: $owner<'_>, block: SecretBlock<'_>, action: fn()) -> usize {
            black_box(&owner);
            black_box(&block);
            black_box(action)();
            drop(block);
            drop(owner);
            black_box($s)
        }

        #[inline(never)]
        fn $name() {
            let mut key = [0; $k];
            for (byte, value) in key.iter_mut().zip(0u8..) {
                *byte = value;
            }
            let key = black_box(key);
            let original_key = key;
            let plain = black_box(hex::<16>("00112233445566778899aabbccddeeff"));
            let cipher = black_box(hex::<16>($expected));
            let mut normal = 0;
            for inverse in [false, true] {
                let (input, expected) = if inverse {
                    (&cipher, &plain)
                } else {
                    (&plain, &cipher)
                };
                // Normal Drop, explicit clear, output outliving its key, and
                // caller-side early Result return, in both operation directions.
                for mode in 0..4 {
                    let mut storage = black_box([[0xa5; $s]; 3]);
                    let mut output = black_box([[0xa5; 16]; 3]);
                    if mode == 3 {
                        let result = caller_result(|| {
                            let owner = $owner::new(&key, &mut storage[1]).unwrap();
                            let block = if inverse {
                                owner.decrypt_block(input, &mut output[1]).unwrap()
                            } else {
                                owner.encrypt_block(input, &mut output[1]).unwrap()
                            };
                            assert_eq!(black_box(block.expose()), expected);
                            Err("caller stopped")
                        });
                        assert_eq!(result, Err("caller stopped"));
                    } else {
                        let owner = $owner::new(&key, &mut storage[1]).unwrap();
                        let block = if inverse {
                            owner.decrypt_block(input, &mut output[1]).unwrap()
                        } else {
                            owner.encrypt_block(input, &mut output[1]).unwrap()
                        };
                        assert_eq!(black_box(block.expose()), expected);
                        match mode {
                            0 => {
                                drop(block);
                                drop(owner);
                            }
                            1 => {
                                block.clear();
                                owner.clear();
                            }
                            2 => {
                                owner.clear();
                                guarded(&storage, &[0; $s]);
                                assert_eq!(black_box(block.expose()), expected);
                                drop(block);
                            }
                            _ => unreachable!(),
                        }
                    }
                    guarded(&storage, &[0; $s]);
                    guarded(&output, &[0; 16]);
                    normal += 1;
                }
            }
            // Public ciphertext deliberately survives both normal key Drop
            // and a caller early return after successful encryption.
            for early in [false, true] {
                let mut storage = black_box([[0xa5; $s]; 3]);
                let mut output = black_box([[0xa5; 16]; 3]);
                let result = caller_result(|| {
                    let owner = $owner::new(&key, &mut storage[1]).unwrap();
                    owner
                        .encrypt_block_public(
                            &plain,
                            &mut output[1],
                            PublicCiphertext::acknowledge(),
                        )
                        .unwrap();
                    if early { Err("caller stopped") } else { Ok(()) }
                });
                assert_eq!(result, if early { Err("caller stopped") } else { Ok(()) });
                guarded(&storage, &[0; $s]);
                guarded(&output, &cipher);
                normal += 1;
            }
            for inverse in [false, true] {
                let mut storage = black_box([[0xa5; $s]; 3]);
                let mut output = black_box([[0xa5; 16]; 3]);
                let owner = $owner::new(&key, &mut storage[1]).unwrap();
                let block = if inverse {
                    owner.decrypt_block(&cipher, &mut output[1]).unwrap()
                } else {
                    owner.encrypt_block(&plain, &mut output[1]).unwrap()
                };
                assert_eq!(
                    black_box(block.expose()),
                    if inverse { &plain } else { &cipher }
                );
                assert_eq!($boundary(owner, block, black_box((|| ()) as fn())), $s);
                guarded(&storage, &[0; $s]);
                guarded(&output, &[0; 16]);
                normal += 1;
            }
            assert_eq!(normal, 12);
            #[cfg(panic = "unwind")]
            let mut unwinds = 0;
            #[cfg(panic = "abort")]
            let unwinds = 0;
            #[cfg(panic = "unwind")]
            {
                // Keys and live secret outputs are inside the unwind scope.
                for inverse in [false, true] {
                    let mut storage = black_box([[0xa5; $s]; 3]);
                    let mut output = black_box([[0xa5; 16]; 3]);
                    unwind(|| {
                        let owner = $owner::new(&key, &mut storage[1]).unwrap();
                        let block = if inverse {
                            owner.decrypt_block(&cipher, &mut output[1]).unwrap()
                        } else {
                            owner.encrypt_block(&plain, &mut output[1]).unwrap()
                        };
                        assert_eq!(
                            black_box(block.expose()),
                            if inverse { &plain } else { &cipher }
                        );
                        caller_panic();
                    });
                    guarded(&storage, &[0; $s]);
                    guarded(&output, &[0; 16]);
                    unwinds += 1;
                }
                for public in [false, true] {
                    let mut storage = black_box([[0xa5; $s]; 3]);
                    let mut output = black_box([[0xa5; 16]; 3]);
                    unwind(|| {
                        let owner = $owner::new(&key, &mut storage[1]).unwrap();
                        if public {
                            owner
                                .encrypt_block_public(
                                    &plain,
                                    &mut output[1],
                                    PublicCiphertext::acknowledge(),
                                )
                                .unwrap();
                        }
                        caller_panic();
                    });
                    guarded(&storage, &[0; $s]);
                    guarded(&output, if public { &cipher } else { &[0xa5; 16] });
                    unwinds += 1;
                }
                // The key lives outside catch_unwind. Only the output drops;
                // using the same key again must still produce the known answer.
                for inverse in [false, true] {
                    let mut storage = black_box([[0xa5; $s]; 3]);
                    let mut output = black_box([[0xa5; 16]; 3]);
                    let owner = $owner::new(&key, &mut storage[1]).unwrap();
                    unwind(|| {
                        let block = if inverse {
                            owner.decrypt_block(&cipher, &mut output[1]).unwrap()
                        } else {
                            owner.encrypt_block(&plain, &mut output[1]).unwrap()
                        };
                        assert_eq!(
                            black_box(block.expose()),
                            if inverse { &plain } else { &cipher }
                        );
                        caller_panic();
                    });
                    guarded(&output, &[0; 16]);
                    assert_eq!(
                        owner
                            .encrypt_block(&plain, &mut output[1])
                            .unwrap()
                            .expose(),
                        cipher
                    );
                    guarded(&output, &[0; 16]);
                    assert_eq!(
                        owner
                            .decrypt_block(&cipher, &mut output[1])
                            .unwrap()
                            .expose(),
                        plain
                    );
                    guarded(&output, &[0; 16]);
                    drop(owner);
                    guarded(&storage, &[0; $s]);
                    unwinds += 1;
                }
                for inverse in [false, true] {
                    let mut storage = black_box([[0xa5; $s]; 3]);
                    let mut output = black_box([[0xa5; 16]; 3]);
                    unwind(|| {
                        let owner = $owner::new(&key, &mut storage[1]).unwrap();
                        let block = if inverse {
                            owner.decrypt_block(&cipher, &mut output[1]).unwrap()
                        } else {
                            owner.encrypt_block(&plain, &mut output[1]).unwrap()
                        };
                        assert_eq!(
                            black_box(block.expose()),
                            if inverse { &plain } else { &cipher }
                        );
                        $boundary(owner, block, black_box((|| caller_panic()) as fn()));
                    });
                    guarded(&storage, &[0; $s]);
                    guarded(&output, &[0; 16]);
                    unwinds += 1;
                }
                assert_eq!(unwinds, 8);
            }
            assert_eq!(black_box(key), original_key);
            assert_eq!(plain, hex::<16>("00112233445566778899aabbccddeeff"));
            assert_eq!(cipher, hex::<16>($expected));
            println!(
                "AES_LINKED_LIFECYCLE: {}; {normal} normal cases; {unwinds} caller unwinds",
                stringify!($owner)
            );
        }
    };
}

owner_cases!(
    key128,
    cleanup_key128,
    Aes128Key,
    16,
    16,
    "69c4e0d86a7b0430d8cdb78070b4c55a"
);
owner_cases!(
    cached128,
    cleanup_cached128,
    Aes128ExpandedKey,
    16,
    176,
    "69c4e0d86a7b0430d8cdb78070b4c55a"
);
owner_cases!(
    key192,
    cleanup_key192,
    Aes192Key,
    24,
    24,
    "dda97ca4864cdfe06eaf70a0ec0d7191"
);
owner_cases!(
    cached192,
    cleanup_cached192,
    Aes192ExpandedKey,
    24,
    208,
    "dda97ca4864cdfe06eaf70a0ec0d7191"
);
owner_cases!(
    key256,
    cleanup_key256,
    Aes256Key,
    32,
    32,
    "8ea2b7ca516745bfeafc49904b496089"
);
owner_cases!(
    cached256,
    cleanup_cached256,
    Aes256ExpandedKey,
    32,
    240,
    "8ea2b7ca516745bfeafc49904b496089"
);

fn main() {
    #[cfg(panic = "unwind")]
    match std::env::args().nth(1).as_deref() {
        Some("unexpected-panic") => unwind(|| panic!("negative control")),
        Some("no-panic") => unwind(|| ()),
        None => (),
        _ => panic!("unknown negative control"),
    }
    key128();
    cached128();
    key192();
    cached192();
    key256();
    cached256();
    #[cfg(panic = "unwind")]
    println!("AES_LINKED_LIFECYCLE: complete; 72 normal cases; 48 caller unwinds");
    #[cfg(panic = "abort")]
    println!(
        "AES_LINKED_LIFECYCLE: complete; 72 normal cases; 0 caller unwinds; abort cleanup not claimed"
    );
}
