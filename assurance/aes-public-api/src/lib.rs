//! Checkout-external AES-128 consumer. Not a mode, protocol or package audit.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(any(
    all(feature = "direct", feature = "facade"),
    not(any(feature = "direct", feature = "facade"))
))]
compile_error!("select exactly one public API route");

#[cfg(feature = "facade")]
pub use brynja::crypto::aes;
#[cfg(feature = "direct")]
pub use brynja_crypto::aes;

/// Exercise construction, explicit declassification and consuming clear through
/// only the selected dependency's public API. Caller input copies are not owned.
pub fn public_block(
    input_key: &[u8; 16],
    key_storage: &mut [u8; 16],
    input: &[u8; 16],
    output: &mut [u8; 16],
) -> Result<(), aes::Error> {
    let key = aes::Aes128Key::new(input_key, key_storage)?;
    let result = key.encrypt_block_public(input, output, aes::PublicCiphertext::acknowledge());
    key.clear();
    result
}

/// Explicit cached schedule route; also instantiated by the no_std target build.
pub fn cached_public_block(
    input_key: &[u8; 16],
    storage: &mut [u8; 176],
    input: &[u8; 16],
    output: &mut [u8; 16],
) -> Result<(), aes::Error> {
    let key = aes::Aes128ExpandedKey::new(input_key, storage)?;
    let result = key.encrypt_block_public(input, output, aes::PublicCiphertext::acknowledge());
    key.clear();
    result
}
