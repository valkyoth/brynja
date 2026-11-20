//! Native observation fixtures using real retained keys and both AES engines.
//! Public FIPS inputs only; no source fault hooks or production qualification.
extern crate std;
use super::*;
use core::hint::black_box;

mod import_tests;
mod import_use_tests;

macro_rules! runner {
    ($run:ident, $owner:ty, $kind:literal) => {
        #[inline(never)]
        fn $run(width: usize, public: bool, inverse: bool) -> Result<(), Error> {
            let plain = tests::answer("00112233445566778899aabbccddeeff")?;
            let cipher = tests::answer(match width {
                16 => "69c4e0d86a7b0430d8cdb78070b4c55a",
                24 => "dda97ca4864cdfe06eaf70a0ec0d7191",
                32 => "8ea2b7ca516745bfeafc49904b496089",
                _ => return Err(Error::SecretMemory),
            })?;
            let input = black_box(if inverse { cipher } else { plain });
            let expected = if inverse { plain } else { cipher };
            let path = if public {
                "public"
            } else if inverse {
                "decrypt"
            } else {
                "encrypt"
            };
            std::println!(
                "BRYNJA_{}_EVIDENCE_CFG={}",
                $kind,
                cfg!(brynja_fault_evidence)
            );
            std::println!("BRYNJA_{}_CASE={width}:{path}", $kind);
            let mut key = [0; 32];
            for (byte, value) in key.iter_mut().zip(0u8..32) {
                *byte = value;
            }
            let mut primary = [0x91; 32];
            let mut secondary = [0x92; 32];
            let mut output = [0x91; 16];
            let accepted;
            {
                let mut owner = <$owner>::new(
                    black_box(key.get(..width).ok_or(Error::SecretMemory)?),
                    primary.get_mut(..width).ok_or(Error::SecretMemory)?,
                    secondary.get_mut(..width).ok_or(Error::SecretMemory)?,
                )?;
                accepted = if public {
                    let result = black_box(&mut owner).encrypt_public(
                        &input,
                        &mut output,
                        PublicCiphertext::acknowledge(),
                    );
                    if result.is_ok() {
                        assert_eq!(output, expected);
                        true
                    } else {
                        assert_eq!(output, [0x91; 16]);
                        false
                    }
                } else {
                    let accepted = match black_box(&mut owner).secret(&input, &mut output, inverse)
                    {
                        Ok(block) => {
                            assert_eq!(block.expose(), &expected);
                            drop(block);
                            true
                        }
                        Err(_) => false,
                    };
                    assert_eq!(output, [0; 16]);
                    accepted
                };
                if accepted {
                    // A healthy owner remains reusable after the observed operation.
                    owner.encrypt_public(&plain, &mut output, PublicCiphertext::acknowledge())?;
                    assert_eq!(output, cipher);
                } else {
                    // Rejection must retire the real owner for BOTH routes.
                    output.fill(0x91);
                    assert!(
                        owner
                            .encrypt_public(&plain, &mut output, PublicCiphertext::acknowledge())
                            .is_err()
                    );
                    assert_eq!(output, [0x91; 16]);
                    assert!(owner.secret(&cipher, &mut output, true).is_err());
                    assert_eq!(output, [0; 16]);
                }
            }
            for (storage, sentinel) in [(&primary, 0x91), (&secondary, 0x92)] {
                assert!(
                    storage
                        .get(..width)
                        .ok_or(Error::SecretMemory)?
                        .iter()
                        .all(|v| *v == 0)
                );
                assert!(
                    storage
                        .get(width..)
                        .ok_or(Error::SecretMemory)?
                        .iter()
                        .all(|v| *v == sentinel)
                );
            }
            std::println!("BRYNJA_{}_STORAGE_CLEARED", $kind);
            std::println!(
                "BRYNJA_{}_{}",
                $kind,
                if accepted {
                    "ACCEPTED"
                } else {
                    "REJECTED_RETIRED"
                }
            );
            Ok(())
        }
    };
}

runner!(run_cached, Cached<'_>, "CACHED");
runner!(run_ephemeral, ephemeral::Ephemeral<'_>, "EPHEMERAL");

macro_rules! fixture {
    ($name:ident, $width:literal, $public:literal, $inverse:literal) => {
        fixture!($name, $width, $public, $inverse, run_cached);
    };
    ($name:ident, $width:literal, $public:literal, $inverse:literal, $run:ident) => {
        #[test]
        fn $name() -> Result<(), Error> {
            $run($width, $public, $inverse)
        }
    };
}

fixture!(native_cached_128_public, 16, true, false);
fixture!(native_cached_192_public, 24, true, false);
fixture!(native_cached_256_public, 32, true, false);
fixture!(native_cached_128_encrypt, 16, false, false);
fixture!(native_cached_192_encrypt, 24, false, false);
fixture!(native_cached_256_encrypt, 32, false, false);
fixture!(native_cached_128_decrypt, 16, false, true);
fixture!(native_cached_192_decrypt, 24, false, true);
fixture!(native_cached_256_decrypt, 32, false, true);
fixture!(native_ephemeral_128_public, 16, true, false, run_ephemeral);
fixture!(native_ephemeral_192_public, 24, true, false, run_ephemeral);
fixture!(native_ephemeral_256_public, 32, true, false, run_ephemeral);
fixture!(
    native_ephemeral_128_encrypt,
    16,
    false,
    false,
    run_ephemeral
);
fixture!(
    native_ephemeral_192_encrypt,
    24,
    false,
    false,
    run_ephemeral
);
fixture!(
    native_ephemeral_256_encrypt,
    32,
    false,
    false,
    run_ephemeral
);
fixture!(native_ephemeral_128_decrypt, 16, false, true, run_ephemeral);
fixture!(native_ephemeral_192_decrypt, 24, false, true, run_ephemeral);
fixture!(native_ephemeral_256_decrypt, 32, false, true, run_ephemeral);
