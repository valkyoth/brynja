//! Hardened cSHAKE root/leaf dispatch; no ordinary hash state.
use super::{Error, shape};
use brynja_core::{clear_owned_region, copy_secret_region};
use brynja_hash_sha3::{
    Fips202BitString as Bits, Fips202Output, HardenedCshake128, HardenedCshake128Setup,
    HardenedCshake256, HardenedCshake256Setup,
};

pub(super) enum State {
    Empty,
    Setup128(HardenedCshake128Setup),
    Setup256(HardenedCshake256Setup),
    A(HardenedCshake128),
    B(HardenedCshake256),
}
impl State {
    pub(super) fn leaf(identity: u64) -> Result<Self, Error> {
        let empty = Bits::new(&[], 0).map_err(|_| Error::Bits)?;
        match identity {
            1 | 3 => HardenedCshake128::new_bits(empty, empty).map(Self::A),
            2 | 4 => HardenedCshake256::new_bits(empty, empty).map(Self::B),
            _ => return Err(Error::Identity),
        }
        .map_err(|_| Error::Crypto)
    }
    pub(super) fn setup(identity: u64, bits: u128) -> Result<Self, Error> {
        let name = Bits::new(b"ParallelHash", 8).map_err(|_| Error::Bits)?;
        match identity {
            1 | 3 => {
                let mut s = HardenedCshake128Setup::new(96, bits).map_err(|_| Error::Crypto)?;
                s.name(name).map_err(|_| Error::Crypto)?;
                Ok(Self::Setup128(s))
            }
            2 | 4 => {
                let mut s = HardenedCshake256Setup::new(96, bits).map_err(|_| Error::Crypto)?;
                s.name(name).map_err(|_| Error::Crypto)?;
                Ok(Self::Setup256(s))
            }
            _ => Err(Error::Identity),
        }
    }
    pub(super) fn custom(&mut self, input: Bits<'_>) -> Result<(), Error> {
        match self {
            Self::Setup128(s) => s.customization(input),
            Self::Setup256(s) => s.customization(input),
            _ => return Err(Error::State),
        }
        .map_err(|_| Error::Crypto)
    }
    pub(super) fn finish_custom(&mut self) -> Result<(), Error> {
        *self = match self {
            Self::Setup128(s) => Self::A(s.finish_erasing_source().map_err(|_| Error::Crypto)?),
            Self::Setup256(s) => Self::B(s.finish_erasing_source().map_err(|_| Error::Crypto)?),
            _ => return Err(Error::State),
        };
        Ok(())
    }
    pub(super) fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        match self {
            Self::A(s) => s.update(input),
            Self::B(s) => s.update(input),
            _ => return Err(Error::State),
        }
        .map_err(|_| Error::Crypto)
    }
    pub(super) fn finish(&mut self, tail: Bits<'_>) -> Result<(), Error> {
        match self {
            Self::A(s) => s.enter_squeezing_in_place(Some(tail)),
            Self::B(s) => s.enter_squeezing_in_place(Some(tail)),
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
        shape(output.len(), last)?;
        let mut scratch = Scratch([0; 1024]);
        let stage = scratch.0.get_mut(..output.len()).ok_or(Error::Length)?;
        let secret = if terminal {
            let bits = Fips202Output::new(stage, last).map_err(|_| Error::Bits)?;
            match self {
                Self::A(s) => s.squeeze_final_bits_secret_in_place(bits),
                Self::B(s) => s.squeeze_final_bits_secret_in_place(bits),
                _ => return Err(Error::State),
            }
        } else {
            match self {
                Self::A(s) => s.squeeze_secret_in_place(stage),
                Self::B(s) => s.squeeze_secret_in_place(stage),
                _ => return Err(Error::State),
            }
        }
        .map_err(|_| Error::Crypto)?;
        copy_secret_region(output, secret.expose()).map_err(|_| Error::Copy)
    }
}
struct Scratch([u8; 1024]);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = clear_owned_region(&mut self.0);
    }
}
