use crate::aes;

macro_rules! consumers {
    ($public:ident, $cached_public:ident, $decrypt:ident, $cached_decrypt:ident,
     $key:ident, $cached:ident, $k:literal, $s:literal) => {
        /// Explicit public encryption through the selected public dependency.
        pub fn $public(
            input_key: &[u8; $k],
            storage: &mut [u8; $k],
            input: &[u8; 16],
            output: &mut [u8; 16],
        ) -> Result<(), aes::Error> {
            let key = aes::$key::new(input_key, storage)?;
            let result =
                key.encrypt_block_public(input, output, aes::PublicCiphertext::acknowledge());
            key.clear();
            result
        }

        /// Cached public encryption through the selected public dependency.
        pub fn $cached_public(
            input_key: &[u8; $k],
            storage: &mut [u8; $s],
            input: &[u8; 16],
            output: &mut [u8; 16],
        ) -> Result<(), aes::Error> {
            let key = aes::$cached::new(input_key, storage)?;
            let result =
                key.encrypt_block_public(input, output, aes::PublicCiphertext::acknowledge());
            key.clear();
            result
        }

        /// Secret output remains owned independently of the ephemeral key.
        pub fn $decrypt<'out>(
            input_key: &[u8; $k],
            storage: &mut [u8; $k],
            input: &[u8; 16],
            output: &'out mut [u8; 16],
        ) -> Result<aes::SecretBlock<'out>, aes::Error> {
            let key = aes::$key::new(input_key, storage)?;
            let result = key.decrypt_block(input, output);
            key.clear();
            result
        }

        /// Secret output remains owned independently of the cached key.
        pub fn $cached_decrypt<'out>(
            input_key: &[u8; $k],
            storage: &mut [u8; $s],
            input: &[u8; 16],
            output: &'out mut [u8; 16],
        ) -> Result<aes::SecretBlock<'out>, aes::Error> {
            let key = aes::$cached::new(input_key, storage)?;
            let result = key.decrypt_block(input, output);
            key.clear();
            result
        }
    };
}

consumers!(
    aes192_public,
    aes192_cached_public,
    aes192_decrypt,
    aes192_cached_decrypt,
    Aes192Key,
    Aes192ExpandedKey,
    24,
    208
);
consumers!(
    aes256_public,
    aes256_cached_public,
    aes256_decrypt,
    aes256_cached_decrypt,
    Aes256Key,
    Aes256ExpandedKey,
    32,
    240
);
