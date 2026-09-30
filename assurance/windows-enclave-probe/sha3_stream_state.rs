//! Dispatch only existing first-party erasing states. SHAKE uses cSHAKE with
//! empty N/S, whose equivalence is independently checked by the oracle tests.
use super::{Algorithm, Error, Scratch};
use brynja_core::copy_secret_region;
use brynja_hash_sha3::{
    Fips202BitString, Fips202Output, HardenedCshake128, HardenedCshake128Setup, HardenedCshake256,
    HardenedCshake256Setup, HardenedSha3_224, HardenedSha3_256, HardenedSha3_384, HardenedSha3_512,
};

pub(super) enum State {
    Empty,
    A(HardenedSha3_224),
    B(HardenedSha3_256),
    C(HardenedSha3_384),
    D(HardenedSha3_512),
    X(HardenedCshake128),
    Y(HardenedCshake256),
    P(HardenedCshake128Setup),
    Q(HardenedCshake256Setup),
}
impl State {
    pub(super) fn setup(algorithm: Algorithm, name: u128, custom: u128) -> Result<Self, Error> {
        match algorithm {
            Algorithm::Cshake128 => HardenedCshake128Setup::new(name, custom).map(Self::P),
            Algorithm::Cshake256 => HardenedCshake256Setup::new(name, custom).map(Self::Q),
            _ => return Err(Error::Identity),
        }
        .map_err(|_| Error::Crypto)
    }
    pub(super) fn setup_chunk(
        &mut self,
        name: bool,
        input: Fips202BitString<'_>,
    ) -> Result<(), Error> {
        match self {
            Self::P(s) => {
                if name {
                    s.name(input)
                } else {
                    s.customization(input)
                }
            }
            Self::Q(s) => {
                if name {
                    s.name(input)
                } else {
                    s.customization(input)
                }
            }
            _ => return Err(Error::State),
        }
        .map_err(|_| Error::Crypto)
    }
    pub(super) fn finish_setup(&mut self) -> Result<(), Error> {
        *self = match core::mem::replace(self, Self::Empty) {
            Self::P(s) => Self::X(s.finish().map_err(|_| Error::Crypto)?),
            Self::Q(s) => Self::Y(s.finish().map_err(|_| Error::Crypto)?),
            _ => return Err(Error::State),
        };
        Ok(())
    }
    pub(super) fn new(
        algorithm: Algorithm,
        name: Fips202BitString<'_>,
        custom: Fips202BitString<'_>,
    ) -> Result<Self, Error> {
        if name.bit_len() > 8192 || custom.bit_len() > 8192 {
            return Err(Error::Length);
        }
        if !matches!(algorithm, Algorithm::Cshake128 | Algorithm::Cshake256)
            && (name.bit_len() != 0 || custom.bit_len() != 0)
        {
            return Err(Error::Identity);
        }
        Ok(match algorithm {
            Algorithm::Sha3_224 => Self::A(HardenedSha3_224::new()),
            Algorithm::Sha3_256 => Self::B(HardenedSha3_256::new()),
            Algorithm::Sha3_384 => Self::C(HardenedSha3_384::new()),
            Algorithm::Sha3_512 => Self::D(HardenedSha3_512::new()),
            Algorithm::Shake128 | Algorithm::Cshake128 => {
                Self::X(HardenedCshake128::new_bits(name, custom).map_err(|_| Error::Crypto)?)
            }
            Algorithm::Shake256 | Algorithm::Cshake256 => {
                Self::Y(HardenedCshake256::new_bits(name, custom).map_err(|_| Error::Crypto)?)
            }
        })
    }
    pub(super) fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        match self {
            Self::A(s) => s.update(input),
            Self::B(s) => s.update(input),
            Self::C(s) => s.update(input),
            Self::D(s) => s.update(input),
            Self::X(s) => s.update(input),
            Self::Y(s) => s.update(input),
            Self::Empty | Self::P(_) | Self::Q(_) => return Err(Error::State),
        }
        .map_err(|_| Error::Crypto)
    }
    pub(super) fn finish_fixed(
        &mut self,
        input: Fips202BitString<'_>,
        output: &mut [u8],
    ) -> Result<(), Error> {
        let mut scratch = Scratch([0; 1024]);
        let staging = scratch.0.get_mut(..output.len()).ok_or(Error::Length)?;
        macro_rules! finish {
            ($state:expr) => {{
                let result = $state
                    .finalize_bits_secret(input, staging)
                    .map_err(|_| Error::Crypto)?;
                copy_secret_region(output, result.expose()).map_err(|_| Error::Copy)
            }};
        }
        match core::mem::replace(self, Self::Empty) {
            Self::A(s) => finish!(s),
            Self::B(s) => finish!(s),
            Self::C(s) => finish!(s),
            Self::D(s) => finish!(s),
            _ => Err(Error::State),
        }
    }
    pub(super) fn finish_xof(&mut self, input: Fips202BitString<'_>) -> Result<(), Error> {
        match self {
            Self::X(s) => s.enter_squeezing_in_place(Some(input)),
            Self::Y(s) => s.enter_squeezing_in_place(Some(input)),
            _ => return Err(Error::State),
        }
        .map_err(|_| Error::Crypto)
    }
    pub(super) fn squeeze(
        &mut self,
        output: &mut [u8],
        last: u8,
        terminal: bool,
    ) -> Result<(), Error> {
        let mut scratch = Scratch([0; 1024]);
        let staging = scratch.0.get_mut(..output.len()).ok_or(Error::Length)?;
        macro_rules! read {
            ($state:expr) => {{
                let result = if terminal {
                    $state.squeeze_final_bits_secret_in_place(
                        Fips202Output::new(staging, last).map_err(|_| Error::Bits)?,
                    )
                } else {
                    $state.squeeze_secret_in_place(staging)
                }
                .map_err(|_| Error::Crypto)?;
                copy_secret_region(output, result.expose()).map_err(|_| Error::Copy)
            }};
        }
        match self {
            Self::X(s) => read!(s),
            Self::Y(s) => read!(s),
            _ => Err(Error::State),
        }?;
        if terminal {
            *self = Self::Empty;
        }
        Ok(())
    }
}
