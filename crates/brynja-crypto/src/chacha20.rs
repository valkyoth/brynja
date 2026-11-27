//! Raw RFC 8439 stream cipher. This compatibility path re-exports the standalone
//! implementation; it does not authenticate ciphertext or allocate nonces.
pub use brynja_cipher_chacha::{ChaCha20, Error};

#[cfg(test)]
mod tests {
    #[test]
    fn owners_and_errors_cross_import_paths_without_conversion() {
        let key = [0; 32];
        let mut stream: super::ChaCha20<'_> =
            brynja_cipher_chacha::ChaCha20::new(&key, [0; 12], u32::MAX);
        let direct: &mut brynja_cipher_chacha::ChaCha20<'_> = &mut stream;
        let result: Result<(), super::Error> = direct.apply_keystream_in_place(&mut [0; 65]);
        assert_eq!(result, Err(brynja_cipher_chacha::Error::Exhausted));
    }
}
