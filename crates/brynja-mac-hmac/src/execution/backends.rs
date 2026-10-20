use super::Authority;
use crate::{Error, Fips202BitString, Sha2BitString};
use brynja_hash_sha2::hardened_execution as sha2;
use brynja_hash_sha3::hardened_execution as sha3;

// Kept in a private module: downstream code cannot substitute a hash owner.
pub trait Backend<'a>: crate::Algorithm {
    type CpuState;
    fn create(owner: &'a Authority) -> Result<Self::CpuState, Error>;
    fn update_cpu(state: &mut Self::CpuState, input: &[u8]) -> Result<(), Error>;
    fn finish_cpu(
        state: Self::CpuState,
        input: Option<Self::FinalInput<'_>>,
        output: &mut [u8],
        consume: impl FnOnce(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error>;
    fn outer_cpu(
        mut state: Self::CpuState,
        digest: &[u8],
        output: &mut [u8],
        consume: impl FnOnce(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        Self::update_cpu(&mut state, digest)?;
        Self::finish_cpu(state, None, output, consume)
    }
}

fn sha2_error(error: sha2::Error) -> Error {
    match error {
        sha2::Error::Backend(error) => Error::Backend(error),
        sha2::Error::MessageTooLong => Error::MessageTooLong,
        _ => Error::ExecutionFailed,
    }
}

fn sha2_digest<'b>(result: &'b sha2::SecretOutput<'_>) -> &'b [u8] {
    result.digest.expose()
}

fn sha3_digest<'b>(result: &'b brynja_hash_sha3::HardenedSha3SecretOutput<'_>) -> &'b [u8] {
    result.expose()
}

pub(super) fn sha3_error(error: sha3::Error) -> Error {
    match error {
        sha3::Error::Backend(error) => Error::Backend(error),
        // Unlike SHA-2's atomic length preflight, SHA-3's operation guard
        // cancels its owner on overflow. Do not preserve the HMAC stream.
        _ => Error::ExecutionFailed,
    }
}

macro_rules! backend {
    ($name:ident, $module:ident, $bits:ident, $create:expr, $error:ident, $digest:expr) => {
        impl<'a> Backend<'a> for crate::$name {
            type CpuState = $module::$name<'a>;
            fn create(owner: &'a Authority) -> Result<Self::CpuState, Error> {
                ($create)(owner)
            }
            fn update_cpu(state: &mut Self::CpuState, input: &[u8]) -> Result<(), Error> {
                state.update(input).map_err($error)
            }
            fn finish_cpu(
                state: Self::CpuState,
                input: Option<$bits<'_>>,
                output: &mut [u8],
                consume: impl FnOnce(&[u8]) -> Result<(), Error>,
            ) -> Result<(), Error> {
                let result = match input {
                    None => state.finalize_secret(output),
                    Some(bits) => state.finalize_bits_secret(bits, output),
                }
                .map_err($error)?;
                consume(($digest)(&result))
            }
        }
    };
}

macro_rules! sha2_backend {
    ($name:ident) => {
        backend!(
            $name,
            sha2,
            Sha2BitString,
            |owner| sha2::$name::new(sha2::Execution::from_static(owner).map_err(sha2_error)?)
                .map_err(sha2_error),
            sha2_error,
            sha2_digest
        );
    };
}

macro_rules! sha3_backend {
    ($name:ident) => {
        backend!(
            $name,
            sha3,
            Fips202BitString,
            |owner| sha3::$name::new(
                sha3::KeccakSession::from_static(owner).map_err(Error::Backend)?
            )
            .map_err(sha3_error),
            sha3_error,
            sha3_digest
        );
    };
}

sha2_backend!(Sha224);
sha2_backend!(Sha256);
sha2_backend!(Sha384);
sha2_backend!(Sha512);
sha2_backend!(Sha512_224);
sha2_backend!(Sha512_256);
sha3_backend!(Sha3_224);
sha3_backend!(Sha3_256);
sha3_backend!(Sha3_384);
sha3_backend!(Sha3_512);

impl<'a, const T: u16> Backend<'a> for crate::Sha512T<T> {
    type CpuState = sha2::Sha512T<'a>;
    fn create(owner: &'a Authority) -> Result<Self::CpuState, Error> {
        let parameter =
            brynja_hash_sha2::Sha512TBits::new(T).map_err(|_| Error::AlgorithmParameter)?;
        sha2::Sha512T::new(
            parameter,
            sha2::Execution::from_static(owner).map_err(sha2_error)?,
        )
        .map_err(sha2_error)
    }
    fn update_cpu(state: &mut Self::CpuState, input: &[u8]) -> Result<(), Error> {
        state.update(input).map_err(sha2_error)
    }
    fn finish_cpu(
        state: Self::CpuState,
        input: Option<Sha2BitString<'_>>,
        output: &mut [u8],
        consume: impl FnOnce(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let result = match input {
            None => state.finalize_secret(output),
            Some(bits) => state.finalize_bits_secret(bits, output),
        }
        .map_err(sha2_error)?;
        consume(result.digest.as_bytes())
    }
    fn outer_cpu(
        state: Self::CpuState,
        digest: &[u8],
        output: &mut [u8],
        consume: impl FnOnce(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let valid = u8::try_from(if T.is_multiple_of(8) { 8 } else { T % 8 })
            .map_err(|_| Error::AlgorithmParameter)?;
        let input = Sha2BitString::new(digest, valid).map_err(|_| Error::ExecutionFailed)?;
        Self::finish_cpu(state, Some(input), output, consume)
    }
}
