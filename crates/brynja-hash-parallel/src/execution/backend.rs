use super::{Error, Mode, Report};
use crate::{Fips202BitString, Fips202Output};
use brynja_hash_sha3::{
    HardenedCshake128, HardenedCshake256, HardenedSha3SecretOutput, hardened_execution as cpu,
};

pub(super) enum State<'a> {
    Portable128(HardenedCshake128),
    Portable256(HardenedCshake256),
    Accelerated128(cpu::Cshake128<'a>),
    Accelerated256(cpu::Cshake256<'a>),
}
macro_rules! dispatch {
    ($s:ident, $method:ident($($arg:expr),*)) => {
        match $s {
            Self::Portable128(s) => s.$method($($arg),*).map_err(Error::from),
            Self::Portable256(s) => s.$method($($arg),*).map_err(Error::from),
            Self::Accelerated128(s) => s.$method($($arg),*).map_err(Error::from),
            Self::Accelerated256(s) => s.$method($($arg),*).map_err(Error::from),
        }
    };
}
impl<'a> State<'a> {
    pub(super) fn new(
        mode: Mode<'a>,
        wide: bool,
        root: bool,
        custom: Fips202BitString<'_>,
    ) -> Result<Self, Error> {
        let name = super::bits(if root { b"ParallelHash" } else { b"" })?;
        let session = match mode {
            Mode::Portable | Mode::Prefer(None) => None,
            Mode::Prefer(Some(s)) | Mode::Require(Some(s)) => Some(s),
            Mode::Require(None) => return Err(Error::AccelerationUnavailable),
        };
        match (wide, session) {
            (false, None) => Ok(Self::Portable128(HardenedCshake128::new_bits(
                name, custom,
            )?)),
            (true, None) => Ok(Self::Portable256(HardenedCshake256::new_bits(
                name, custom,
            )?)),
            (false, Some(s)) => Ok(Self::Accelerated128(cpu::Cshake128::new_bits(
                s, name, custom,
            )?)),
            (true, Some(s)) => Ok(Self::Accelerated256(cpu::Cshake256::new_bits(
                s, name, custom,
            )?)),
        }
    }
    pub(super) fn report(&self) -> Option<Report> {
        match self {
            Self::Portable128(_) | Self::Portable256(_) => None,
            Self::Accelerated128(s) => Some(s.report()),
            Self::Accelerated256(s) => Some(s.report()),
        }
    }
    pub(super) fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        dispatch!(self, update(input))
    }
    pub(super) fn finish(&mut self, tail: Fips202BitString<'_>) -> Result<(), Error> {
        match self {
            Self::Portable128(s) => s.enter_squeezing_in_place(Some(tail)).map_err(Error::from),
            Self::Portable256(s) => s.enter_squeezing_in_place(Some(tail)).map_err(Error::from),
            Self::Accelerated128(s) => s.enter_squeezing_in_place(tail).map_err(Error::from),
            Self::Accelerated256(s) => s.enter_squeezing_in_place(tail).map_err(Error::from),
        }
    }
    pub(super) fn secret<'out>(
        &mut self,
        output: &'out mut [u8],
        valid: u8,
        terminal: bool,
    ) -> Result<HardenedSha3SecretOutput<'out>, Error> {
        if !terminal {
            return dispatch!(self, squeeze_secret_in_place(output));
        }
        match self {
            Self::Portable128(s) => s
                .squeeze_final_bits_secret_in_place(
                    Fips202Output::new(output, valid).map_err(|_| Error::OutputLength)?,
                )
                .map_err(Error::from),
            Self::Portable256(s) => s
                .squeeze_final_bits_secret_in_place(
                    Fips202Output::new(output, valid).map_err(|_| Error::OutputLength)?,
                )
                .map_err(Error::from),
            Self::Accelerated128(s) => s
                .squeeze_final_bits_secret_in_place(output, valid)
                .map_err(Error::from),
            Self::Accelerated256(s) => s
                .squeeze_final_bits_secret_in_place(output, valid)
                .map_err(Error::from),
        }
    }
    #[inline(never)]
    pub(super) fn wipe(&mut self) {
        match self {
            Self::Portable128(s) => s.wipe_in_place(),
            Self::Portable256(s) => s.wipe_in_place(),
            Self::Accelerated128(s) => s.cancel(),
            Self::Accelerated256(s) => s.cancel(),
        }
    }
}
impl Drop for State<'_> {
    fn drop(&mut self) {
        self.wipe();
    }
}
