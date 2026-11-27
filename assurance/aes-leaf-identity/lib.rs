//! Downstream type-identity and known-answer checks; public FIPS 197 examples.
#![no_std]
#![forbid(unsafe_code)]

use brynja::crypto::aes as facade;
use brynja_cipher_aes::aes as leaf;
use brynja_crypto::aes as compat;

macro_rules! width {
    ($function:ident, $key:ident, $cached:ident, $n:literal, $s:literal, $expected:expr) => {
        pub fn $function() -> Result<(), compat::Error> {
            let input = 0x00112233445566778899aabbccddeeff_u128.to_be_bytes();
            let expected = $expected.to_be_bytes();
            let bytes: [u8; $n] = core::array::from_fn(|i| i as u8);
            let mut key_storage = [0xa5; $n];
            let mut schedule = [0xa5; $s];
            let mut block_storage = [0xa5; 16];
            let key: compat::$key<'_> = leaf::$key::new(&bytes, &mut key_storage)?;
            let cached: leaf::$cached<'_> = facade::$cached::new(&bytes, &mut schedule)?;
            let output: facade::SecretBlock<'_> = key.encrypt_block(&input, &mut block_storage)?;
            assert_eq!(output.expose(), &expected);
            output.clear();
            let plain: compat::SecretBlock<'_> =
                cached.decrypt_block(&expected, &mut block_storage)?;
            assert_eq!(plain.expose(), &input);
            drop(plain);
            key.clear();
            drop(cached);
            assert_eq!(block_storage, [0; 16]);
            assert_eq!(key_storage, [0; $n]);
            assert_eq!(schedule, [0; $s]);
            Ok(())
        }
    };
}

width!(
    aes128,
    Aes128Key,
    Aes128ExpandedKey,
    16,
    176,
    0x69c4e0d86a7b0430d8cdb78070b4c55a_u128
);
width!(
    aes192,
    Aes192Key,
    Aes192ExpandedKey,
    24,
    208,
    0xdda97ca4864cdfe06eaf70a0ec0d7191_u128
);
width!(
    aes256,
    Aes256Key,
    Aes256ExpandedKey,
    32,
    240,
    0x8ea2b7ca516745bfeafc49904b496089_u128
);
