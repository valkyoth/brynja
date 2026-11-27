//! Compatibility import for the standalone raw AES block owners.
//! Only this crate's own features may expose its optional public modules.
#[cfg(not(feature = "hazmat-aes-block"))]
pub(crate) use brynja_cipher_aes::__mode::{
    Aes128ExpandedKey, Aes192ExpandedKey, Aes256ExpandedKey, Error, SecretBlock,
};
#[cfg(feature = "hazmat-aes-block")]
pub use brynja_cipher_aes::aes::{
    AES192_EXPANDED_KEY_BYTES, AES192_KEY_BYTES, AES256_EXPANDED_KEY_BYTES, AES256_KEY_BYTES,
    Aes128ExpandedKey, Aes128Key, Aes192ExpandedKey, Aes192Key, Aes256ExpandedKey, Aes256Key,
    BLOCK_BYTES, EXPANDED_KEY_BYTES, Error, KEY_BYTES, PublicCiphertext, SecretBlock,
};

#[cfg(all(
    not(feature = "aes-static-execution"),
    any(feature = "aes-gcm-execution", feature = "gmac-execution")
))]
pub(crate) use brynja_cipher_aes::__mode::execution;
#[cfg(feature = "aes-static-execution")]
pub use brynja_cipher_aes::aes::execution;

#[cfg(all(feature = "hazmat-aes-block", feature = "external-key-provider"))]
pub use brynja_cipher_aes::aes::provider;
