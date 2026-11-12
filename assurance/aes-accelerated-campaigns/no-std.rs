//! Compile-only downstream accelerated owners, without std or an allocator.
#![no_std]
#![forbid(unsafe_code)]

use api::PublicCiphertext;
use api::execution::*;
#[cfg(feature = "facade")]
use brynja::crypto::aes as api;
#[cfg(feature = "direct")]
use brynja_crypto::aes as api;

pub fn static_authority(kernel: Kernel) -> Result<Authority, Error> {
    Authority::new(kernel).map_err(Error::from)
}

macro_rules! width {
    ($name:ident, $raw:ident, $cached:ident, $k:literal, $s:literal) => {
        pub mod $name {
            use super::*;

            #[inline(never)]
            pub fn exercise(authority: &Authority, input_key: &[u8; $k]) -> Result<(), Error> {
                let mut raw = [0u8; $k];
                let mut schedule = [0u8; $s];
                let key = $raw::new(authority, input_key, &mut raw)?;
                let cached = $cached::new(authority, input_key, &mut schedule)?;
                let input = [0u8; 16];
                let mut output = [0u8; 16];
                key.encrypt_block(&input, &mut output)?.clear();
                key.decrypt_block(&input, &mut output)?.clear();
                key.encrypt_block_public(&input, &mut output, PublicCiphertext::acknowledge())?;
                cached.encrypt_block(&input, &mut output)?.clear();
                cached.decrypt_block(&input, &mut output)?.clear();
                cached.encrypt_block_public(
                    &input,
                    &mut output,
                    PublicCiphertext::acknowledge(),
                )?;
                key.clear();
                cached.clear();
                Ok(())
            }
        }
    };
}

width!(aes128, Aes128Key, Aes128ExpandedKey, 16, 176);
width!(aes192, Aes192Key, Aes192ExpandedKey, 24, 208);
width!(aes256, Aes256Key, Aes256ExpandedKey, 32, 240);
