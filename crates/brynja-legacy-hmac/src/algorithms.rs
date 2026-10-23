use crate::{BitString, Error};

pub(crate) mod sealed {
    use crate::{BitString, Error};

    // Only the two hardened legacy owners below satisfy this private contract.
    // Rejected updates are atomic. Finalization consumes its state, owns the
    // digest while invoking the callback, and performs no fallible work after it.
    pub trait Hash {
        type State;
        fn start() -> Result<Self::State, Error>;
        fn update(state: &mut Self::State, input: &[u8]) -> Result<(), Error>;
        fn finish(
            state: Self::State,
            tail: Option<BitString<'_>>,
            output: &mut [u8],
            consume: impl FnOnce(&[u8]) -> Result<(), Error>,
        ) -> Result<(), Error>;
    }
}

/// Sealed legacy identity, distinct from every modern HMAC algorithm.
///
/// ```compile_fail
/// struct Forged;
/// impl brynja_legacy_hmac::Algorithm for Forged { const TAG_BYTES: usize = 20; }
/// ```
pub trait Algorithm: sealed::Hash {
    /// Complete byte-aligned digest width.
    const TAG_BYTES: usize;
}

macro_rules! algorithm {
    ($name:ident, $state:ty, $error:ty, $bytes:literal) => {
        #[doc = concat!("Legacy-only HMAC-", stringify!($name), " identity.")]
        pub enum $name {}
        impl Algorithm for $name {
            const TAG_BYTES: usize = $bytes;
        }
        impl sealed::Hash for $name {
            type State = $state;
            fn start() -> Result<Self::State, Error> {
                Ok(<$state>::new())
            }
            fn update(state: &mut Self::State, input: &[u8]) -> Result<(), Error> {
                state.update(input).map_err(|error| match error {
                    <$error>::MessageTooLong => Error::MessageTooLong,
                    _ => Error::SecretMemory,
                })
            }
            fn finish(
                state: Self::State,
                tail: Option<BitString<'_>>,
                output: &mut [u8],
                consume: impl FnOnce(&[u8]) -> Result<(), Error>,
            ) -> Result<(), Error> {
                let result = match tail {
                    Some(tail) => state.finalize_bits_secret(tail, output),
                    None => state.finalize_secret(output),
                };
                let digest = result.map_err(|error| match error {
                    <$error>::MessageTooLong => Error::MessageTooLong,
                    _ => Error::SecretMemory,
                })?;
                consume(digest.expose())
            }
        }
    };
}

algorithm!(
    Sha1,
    brynja_legacy_sha1::HardenedSha1,
    brynja_legacy_sha1::Sha1Error,
    20
);
algorithm!(
    Md5,
    brynja_legacy_md5::HardenedMd5,
    brynja_legacy_md5::Md5Error,
    16
);
