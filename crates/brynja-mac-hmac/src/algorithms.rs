use crate::{Error, Fips202BitString, Sha2BitString};

pub(crate) mod sealed {
    use crate::Error;

    /// Internal composition contract, not a downstream extension point.
    ///
    /// States own their secret cleanup. Rejected updates must not partially
    /// absorb input; a length rejection leaves the stream reusable. Finalizing
    /// consumes the state on every path. `finish` may call `consume` only once,
    /// after hashing succeeds, and must return that callback's result directly:
    /// no fallible work may follow public output commit. Its temporary digest
    /// remains owned and clears on both callback return and recoverable unwind.
    pub trait Hash {
        type State;
        type FinalInput<'a>: Copy;
        fn validate() -> Result<(), Error> {
            Ok(())
        }
        fn start() -> Result<Self::State, Error>;
        fn update(state: &mut Self::State, input: &[u8]) -> Result<(), Error>;
        fn finish(
            state: Self::State,
            output: &mut [u8],
            consume: impl FnOnce(&[u8]) -> Result<(), Error>,
        ) -> Result<(), Error>;
        /// Same consuming/callback contract as `finish`, with a typed final
        /// bit string. The adapter must not round its bit length to bytes.
        fn finish_bits(
            state: Self::State,
            input: Self::FinalInput<'_>,
            output: &mut [u8],
            consume: impl FnOnce(&[u8]) -> Result<(), Error>,
        ) -> Result<(), Error>;
        /// Consumes the outer owner with the exact inner digest. Named hashes
        /// have byte-aligned digests; non-byte digests must override this.
        fn finish_outer(
            mut state: Self::State,
            digest: &[u8],
            output: &mut [u8],
            consume: impl FnOnce(&[u8]) -> Result<(), Error>,
        ) -> Result<(), Error> {
            Self::update(&mut state, digest)?;
            Self::finish(state, output, consume)
        }
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
    /// Exact full digest width; storage rounds up to `TAG_BYTES`.
    const TAG_BITS: usize = Self::TAG_BYTES * 8;
}

macro_rules! algorithm {
    ($marker:ident, $state:path, $block:literal, $tag:literal, $map:ident, $bits:ident) => {
        #[doc = concat!("HMAC identity using the hardened `", stringify!($marker), "` hash owner.")]
        pub enum $marker {}

        impl Algorithm for $marker {
            const BLOCK_BYTES: usize = $block;
            const TAG_BYTES: usize = $tag;
        }

        impl sealed::Hash for $marker {
            type State = $state;
            type FinalInput<'a> = $bits<'a>;

            fn start() -> Result<Self::State, Error> {
                Ok(<$state>::new())
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

            fn finish_bits(
                state: Self::State,
                input: Self::FinalInput<'_>,
                output: &mut [u8],
                consume: impl FnOnce(&[u8]) -> Result<(), Error>,
            ) -> Result<(), Error> {
                let secret = state.finalize_bits_secret(input, output).map_err($map)?;
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

algorithm!(
    Sha224,
    brynja_hash_sha2::HardenedSha224,
    64,
    28,
    sha2_error,
    Sha2BitString
);
algorithm!(
    Sha256,
    brynja_hash_sha2::HardenedSha256,
    64,
    32,
    sha2_error,
    Sha2BitString
);
algorithm!(
    Sha384,
    brynja_hash_sha2::HardenedSha384,
    128,
    48,
    sha2_error,
    Sha2BitString
);
algorithm!(
    Sha512,
    brynja_hash_sha2::HardenedSha512,
    128,
    64,
    sha2_error,
    Sha2BitString
);
algorithm!(
    Sha512_224,
    brynja_hash_sha2::HardenedSha512_224,
    128,
    28,
    sha2_error,
    Sha2BitString
);
algorithm!(
    Sha512_256,
    brynja_hash_sha2::HardenedSha512_256,
    128,
    32,
    sha2_error,
    Sha2BitString
);
algorithm!(
    Sha3_224,
    brynja_hash_sha3::HardenedSha3_224,
    144,
    28,
    sha3_error,
    Fips202BitString
);
algorithm!(
    Sha3_256,
    brynja_hash_sha3::HardenedSha3_256,
    136,
    32,
    sha3_error,
    Fips202BitString
);
algorithm!(
    Sha3_384,
    brynja_hash_sha3::HardenedSha3_384,
    104,
    48,
    sha3_error,
    Fips202BitString
);
algorithm!(
    Sha3_512,
    brynja_hash_sha3::HardenedSha3_512,
    72,
    64,
    sha3_error,
    Fips202BitString
);
