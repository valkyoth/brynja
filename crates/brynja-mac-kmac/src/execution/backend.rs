use super::{Error, Mode, Report};
use crate::packer::Absorb;
use brynja_hash_sha3::{
    Fips202BitString, Fips202Output, HardenedCshake128, HardenedCshake256,
    HardenedSha3SecretOutput, Sha3PublicDeclassification, hardened_execution as accelerated,
};

// Every variant owns a hardened sponge. No ordinary-state alternative exists.
pub(super) enum State<'a> {
    Portable128(HardenedCshake128),
    Portable256(HardenedCshake256),
    Accelerated128(accelerated::Cshake128<'a>),
    Accelerated256(accelerated::Cshake256<'a>),
}

macro_rules! dispatch {
    ($self:ident, $name:ident($($arg:expr),*)) => {
        match $self {
            Self::Portable128(s) => s.$name($($arg),*).map_err(Error::from),
            Self::Portable256(s) => s.$name($($arg),*).map_err(Error::from),
            Self::Accelerated128(s) => s.$name($($arg),*).map_err(Error::from),
            Self::Accelerated256(s) => s.$name($($arg),*).map_err(Error::from),
        }
    };
}

impl<'a> State<'a> {
    pub(super) fn new(
        mode: Mode<'a>,
        wide: bool,
        customization: Fips202BitString<'_>,
    ) -> Result<Self, Error> {
        let name = super::bits(b"KMAC")?;
        let session = match mode {
            Mode::Portable | Mode::Prefer(None) => None,
            Mode::Prefer(Some(session)) | Mode::Require(Some(session)) => Some(session),
            Mode::Require(None) => return Err(Error::AccelerationUnavailable),
        };
        match (wide, session) {
            (false, None) => Ok(Self::Portable128(HardenedCshake128::new_bits(
                name,
                customization,
            )?)),
            (true, None) => Ok(Self::Portable256(HardenedCshake256::new_bits(
                name,
                customization,
            )?)),
            (false, Some(session)) => Ok(Self::Accelerated128(accelerated::Cshake128::new_bits(
                session,
                name,
                customization,
            )?)),
            (true, Some(session)) => Ok(Self::Accelerated256(accelerated::Cshake256::new_bits(
                session,
                name,
                customization,
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

    pub(super) fn finish(&mut self, input: Fips202BitString<'_>) -> Result<(), Error> {
        match self {
            Self::Portable128(s) => s.enter_squeezing_in_place(Some(input)).map_err(Error::from),
            Self::Portable256(s) => s.enter_squeezing_in_place(Some(input)).map_err(Error::from),
            Self::Accelerated128(s) => s.enter_squeezing_in_place(input).map_err(Error::from),
            Self::Accelerated256(s) => s.enter_squeezing_in_place(input).map_err(Error::from),
        }
    }

    pub(super) fn secret<'out>(
        &mut self,
        bytes: &'out mut [u8],
        valid: u8,
        terminal: bool,
    ) -> Result<HardenedSha3SecretOutput<'out>, Error> {
        if !terminal {
            return dispatch!(self, squeeze_secret_in_place(bytes));
        }
        match self {
            Self::Portable128(s) => s
                .squeeze_final_bits_secret_in_place(
                    Fips202Output::new(bytes, valid).map_err(|_| Error::InvalidBitString)?,
                )
                .map_err(Error::from),
            Self::Portable256(s) => s
                .squeeze_final_bits_secret_in_place(
                    Fips202Output::new(bytes, valid).map_err(|_| Error::InvalidBitString)?,
                )
                .map_err(Error::from),
            Self::Accelerated128(s) => s
                .squeeze_final_bits_secret_in_place(bytes, valid)
                .map_err(Error::from),
            Self::Accelerated256(s) => s
                .squeeze_final_bits_secret_in_place(bytes, valid)
                .map_err(Error::from),
        }
    }

    pub(super) fn public(&mut self, bytes: &mut [u8], scratch: &mut [u8]) -> Result<(), Error> {
        let authority = Sha3PublicDeclassification::acknowledge();
        match self {
            Self::Portable128(s) => {
                s.squeeze_public_in_place(scratch, authority)?;
                bytes.copy_from_slice(scratch);
                Ok(())
            }
            Self::Portable256(s) => {
                s.squeeze_public_in_place(scratch, authority)?;
                bytes.copy_from_slice(scratch);
                Ok(())
            }
            Self::Accelerated128(s) => s
                .squeeze_public_in_place(bytes, scratch, authority)
                .map_err(Error::from),
            Self::Accelerated256(s) => s
                .squeeze_public_in_place(bytes, scratch, authority)
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

impl Absorb for State<'_> {
    fn absorb(&mut self, bytes: &[u8]) -> Result<(), Error> {
        dispatch!(self, update(bytes))
    }
}
