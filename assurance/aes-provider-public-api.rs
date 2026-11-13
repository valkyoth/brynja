//! Dependency-free application helpers: supply an already validated adapter.
//! This fixture is compiled against package archives, not a device library.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(any(
    all(feature = "direct", feature = "facade"),
    not(any(feature = "direct", feature = "facade"))
))]
compile_error!("select exactly one public API route");

#[cfg(feature = "facade")]
use brynja::crypto;
#[cfg(feature = "direct")]
use brynja_crypto as crypto;

use crypto::aes::{PublicCiphertext, SecretBlock, provider};

macro_rules! helpers {
    ($backend:ident, $key:ident, $encrypt:ident, $decrypt:ident) => {
        /// Release one ciphertext block from the application's selected binding.
        /// Raw AES is not authenticated message encryption. No fallback or retry.
        pub fn $encrypt<B: provider::$backend>(
            key: &mut provider::$key<B>,
            input: &[u8; 16],
            output: &mut [u8; 16],
        ) -> Result<(), provider::Error> {
            key.encrypt_block_public(input, output, PublicCiphertext::acknowledge())
        }

        /// Keep decrypted bytes in a clearing owner; this does not authenticate.
        pub fn $decrypt<'out, B: provider::$backend>(
            key: &mut provider::$key<B>,
            input: &[u8; 16],
            output: &'out mut [u8; 16],
        ) -> Result<SecretBlock<'out>, provider::Error> {
            key.decrypt_block(input, output)
        }
    };
}

helpers!(Aes128Backend, Aes128ProviderKey, encrypt128, decrypt128);
helpers!(Aes192Backend, Aes192ProviderKey, encrypt192, decrypt192);
helpers!(Aes256Backend, Aes256ProviderKey, encrypt256, decrypt256);
