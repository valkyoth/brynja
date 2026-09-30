//! Existing affine hardware streams; never construct a portable execution route.
use super::{Algorithm, Authority, BitString, Error, Scratch};
use brynja_core::copy_secret_region;
use brynja_hash_sha2::hardened_execution::{Execution, Sha224, Sha256};

pub(super) enum State<'a> {
    A(Sha224<'a>),
    B(Sha256<'a>),
}
impl<'a> State<'a> {
    pub(super) fn new(algorithm: Algorithm, authority: &'a Authority) -> Result<Self, Error> {
        let execution = Execution::from_static(authority).map_err(|_| Error::Backend)?;
        match algorithm {
            Algorithm::Sha224 => Sha224::new(execution)
                .map(Self::A)
                .map_err(|_| Error::Backend),
            Algorithm::Sha256 => Sha256::new(execution)
                .map(Self::B)
                .map_err(|_| Error::Backend),
            _ => Err(Error::Identity),
        }
    }
    pub(super) fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        match self {
            Self::A(state) => state.update(input),
            Self::B(state) => state.update(input),
        }
        .map_err(|_| Error::Backend)
    }
    pub(super) fn finish(self, input: BitString<'_>, output: &mut [u8]) -> Result<(), Error> {
        let mut staging = Scratch([0; 32]);
        let bytes = staging.0.get_mut(..output.len()).ok_or(Error::Length)?;
        let result = match self {
            Self::A(state) => state.finalize_bits_secret(input, bytes),
            Self::B(state) => state.finalize_bits_secret(input, bytes),
        }
        .map_err(|_| Error::Backend)?;
        copy_secret_region(output, result.digest.expose()).map_err(|_| Error::Copy)
    }
}
