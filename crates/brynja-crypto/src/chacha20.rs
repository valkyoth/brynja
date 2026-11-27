//! Raw RFC 8439 stream cipher. This compatibility path re-exports the standalone
//! implementation; it does not authenticate ciphertext or allocate nonces.
pub use brynja_cipher_chacha::{ChaCha20, Error};

#[cfg(test)]
mod tests {
    #[test]
    fn owners_and_errors_cross_import_paths_without_conversion() {
        // This checks the re-export, not cipher behavior. No key or nonce is
        // needed; the public counter_exhaustion test covers the rejected call.
        use core::any::TypeId;
        assert_eq!(
            TypeId::of::<super::ChaCha20<'static>>(),
            TypeId::of::<brynja_cipher_chacha::ChaCha20<'static>>()
        );
        assert_eq!(
            TypeId::of::<super::Error>(),
            TypeId::of::<brynja_cipher_chacha::Error>()
        );
    }
}
