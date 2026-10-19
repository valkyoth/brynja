use crate::Error;

pub(crate) mod sealed {
    use crate::Error;

    pub trait Hash {
        type State;
        fn start() -> Self::State;
        fn update(state: &mut Self::State, input: &[u8]) -> Result<(), Error>;
        fn finish(
            state: Self::State,
            output: &mut [u8],
            consume: impl FnOnce(&[u8]) -> Result<(), Error>,
        ) -> Result<(), Error>;
    }
}

/// Sealed admission to the HMAC construction, not a generic digest blanket impl.
///
/// Only the explicitly listed hardened SHA-2/SHA-3 owners are admitted.
/// Ordinary hashes, XOFs, legacy hashes and downstream implementations cannot
/// substitute their storage, finalization or output behavior.
///
/// ```compile_fail
/// struct Ordinary;
/// impl brynja_mac_hmac::Algorithm for Ordinary {
///     const BLOCK_BYTES: usize = 64;
///     const TAG_BYTES: usize = 32;
/// }
/// ```
pub trait Algorithm: sealed::Hash {
    /// Compression-block width, or SHA-3 sponge rate, in bytes.
    const BLOCK_BYTES: usize;
    /// Full fixed digest width in bytes.
    const TAG_BYTES: usize;
}

macro_rules! algorithm {
    ($marker:ident, $state:path, $block:literal, $tag:literal, $map:ident) => {
        #[doc = concat!("HMAC identity using the hardened `", stringify!($marker), "` hash owner.")]
        pub enum $marker {}

        impl Algorithm for $marker {
            const BLOCK_BYTES: usize = $block;
            const TAG_BYTES: usize = $tag;
        }

        impl sealed::Hash for $marker {
            type State = $state;

            fn start() -> Self::State {
                <$state>::new()
            }

            fn update(state: &mut Self::State, input: &[u8]) -> Result<(), Error> {
                state.update(input).map_err($map)
            }

            fn finish(
                state: Self::State,
                output: &mut [u8],
                consume: impl FnOnce(&[u8]) -> Result<(), Error>,
            ) -> Result<(), Error> {
                let secret = state.finalize_secret(output).map_err($map)?;
                consume(secret.expose())
            }
        }
    };
}

fn sha2_error(error: brynja_hash_sha2::HardenedSha2Error) -> Error {
    match error {
        brynja_hash_sha2::HardenedSha2Error::MessageTooLong => Error::MessageTooLong,
        _ => Error::SecretMemory,
    }
}

fn sha3_error(error: brynja_hash_sha3::HardenedSha3Error) -> Error {
    match error {
        brynja_hash_sha3::HardenedSha3Error::MessageTooLong => Error::MessageTooLong,
        _ => Error::SecretMemory,
    }
}

algorithm!(Sha224, brynja_hash_sha2::HardenedSha224, 64, 28, sha2_error);
algorithm!(Sha256, brynja_hash_sha2::HardenedSha256, 64, 32, sha2_error);
algorithm!(
    Sha384,
    brynja_hash_sha2::HardenedSha384,
    128,
    48,
    sha2_error
);
algorithm!(
    Sha512,
    brynja_hash_sha2::HardenedSha512,
    128,
    64,
    sha2_error
);
algorithm!(
    Sha512_224,
    brynja_hash_sha2::HardenedSha512_224,
    128,
    28,
    sha2_error
);
algorithm!(
    Sha512_256,
    brynja_hash_sha2::HardenedSha512_256,
    128,
    32,
    sha2_error
);
algorithm!(
    Sha3_224,
    brynja_hash_sha3::HardenedSha3_224,
    144,
    28,
    sha3_error
);
algorithm!(
    Sha3_256,
    brynja_hash_sha3::HardenedSha3_256,
    136,
    32,
    sha3_error
);
algorithm!(
    Sha3_384,
    brynja_hash_sha3::HardenedSha3_384,
    104,
    48,
    sha3_error
);
algorithm!(
    Sha3_512,
    brynja_hash_sha3::HardenedSha3_512,
    72,
    64,
    sha3_error
);
