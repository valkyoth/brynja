//! Closed dispatch over existing first-party hardened SHA-2 implementations.
use super::{Algorithm, Error};
use brynja_core::copy_secret_region;
use brynja_hash_sha2::{
    BitString, HardenedSha224, HardenedSha256, HardenedSha384, HardenedSha512, HardenedSha512_224,
    HardenedSha512_256, HardenedSha512T,
};

pub(super) enum State {
    A(HardenedSha224),
    B(HardenedSha256),
    C(HardenedSha384),
    D(HardenedSha512),
    E(HardenedSha512_224),
    F(HardenedSha512_256),
    T(HardenedSha512T),
}
impl State {
    pub(super) fn new(algorithm: Algorithm) -> Self {
        match algorithm {
            Algorithm::Sha224 => Self::A(HardenedSha224::new()),
            Algorithm::Sha256 => Self::B(HardenedSha256::new()),
            Algorithm::Sha384 => Self::C(HardenedSha384::new()),
            Algorithm::Sha512 => Self::D(HardenedSha512::new()),
            Algorithm::Sha512_224 => Self::E(HardenedSha512_224::new()),
            Algorithm::Sha512_256 => Self::F(HardenedSha512_256::new()),
            Algorithm::Sha512T(t) => Self::T(HardenedSha512T::new(t)),
        }
    }
    pub(super) fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        match self {
            Self::A(s) => s.update(input).map_err(|_| Error::Length),
            Self::B(s) => s.update(input).map_err(|_| Error::Length),
            Self::C(s) => s.update(input).map_err(|_| Error::Length),
            Self::D(s) => s.update(input).map_err(|_| Error::Length),
            Self::E(s) => s.update(input).map_err(|_| Error::Length),
            Self::F(s) => s.update(input).map_err(|_| Error::Length),
            Self::T(s) => s.update(input).map_err(|_| Error::Length),
        }
    }
    pub(super) fn finish(self, bits: BitString<'_>, output: &mut [u8]) -> Result<(), Error> {
        // Result owners clear staging on every branch. The retained destination
        // is written using the existing opaque secret-copy boundary, not a
        // public digest API or a copyable digest value.
        let mut staging = super::Scratch([0; 64]);
        let bytes = staging.0.get_mut(..output.len()).ok_or(Error::Length)?;
        macro_rules! finish {
            ($s:expr) => {{
                let result = $s
                    .finalize_bits_secret(bits, bytes)
                    .map_err(|_| Error::Bits)?;
                copy_secret_region(output, result.expose()).map_err(|_| Error::Copy)
            }};
        }
        match self {
            Self::A(s) => finish!(s),
            Self::B(s) => finish!(s),
            Self::C(s) => finish!(s),
            Self::D(s) => finish!(s),
            Self::E(s) => finish!(s),
            Self::F(s) => finish!(s),
            Self::T(s) => {
                let result = s
                    .finalize_bits_secret(bits, bytes)
                    .map_err(|_| Error::Bits)?;
                copy_secret_region(output, result.as_bytes()).map_err(|_| Error::Copy)
            }
        }
    }
}
