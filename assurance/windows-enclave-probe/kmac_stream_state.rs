//! Reuse existing strength-enforcing first-party KMAC APIs, not new framing.
use super::{Algorithm, Error, Scratch};
use brynja_core::copy_secret_region;
use brynja_mac_kmac::{
    Fips202BitString, Fips202Output, Kmac128, Kmac128Setup, Kmac256, Kmac256Setup, KmacXof128,
    KmacXof128Reader, KmacXof256, KmacXof256Reader,
};
pub(super) enum State {
    Empty,
    Setup128(Kmac128Setup),
    Setup256(Kmac256Setup),
    A(Kmac128),
    B(Kmac256),
    X(KmacXof128),
    Y(KmacXof256),
    R(KmacXof128Reader),
    S(KmacXof256Reader),
}
impl State {
    pub(super) fn new(
        algorithm: Algorithm,
        key: Fips202BitString<'_>,
        custom: Fips202BitString<'_>,
    ) -> Result<Self, Error> {
        if key.as_bytes().len() > 1024 || custom.as_bytes().len() > 1024 {
            return Err(Error::Length);
        }
        macro_rules! prepare {
            ($setup:ident, $finish:ident, $variant:ident) => {{
                let mut setup = $setup::new(
                    u128::try_from(key.bit_len()).map_err(|_| Error::Length)?,
                    u128::try_from(custom.bit_len()).map_err(|_| Error::Length)?,
                )
                .map_err(|_| Error::Crypto)?;
                setup.customization(custom).map_err(|_| Error::Crypto)?;
                setup.finish_customization().map_err(|_| Error::Crypto)?;
                setup.key(key).map_err(|_| Error::Crypto)?;
                setup
                    .$finish()
                    .map(Self::$variant)
                    .map_err(|_| Error::Crypto)
            }};
        }
        match algorithm {
            Algorithm::Kmac128 => prepare!(Kmac128Setup, finish, A),
            Algorithm::Kmac256 => prepare!(Kmac256Setup, finish, B),
            Algorithm::KmacXof128 => prepare!(Kmac128Setup, finish_xof, X),
            Algorithm::KmacXof256 => prepare!(Kmac256Setup, finish_xof, Y),
        }
    }
    pub(super) fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        match self {
            Self::A(s) => s.update(input),
            Self::B(s) => s.update(input),
            Self::X(s) => s.update(input),
            Self::Y(s) => s.update(input),
            _ => return Err(Error::State),
        }
        .map_err(|_| Error::Crypto)
    }
    pub(super) fn fixed(
        &mut self,
        input: Fips202BitString<'_>,
        output: &mut [u8],
        last: u8,
    ) -> Result<(), Error> {
        let mut scratch = Scratch([0; 1024]);
        let staging = Fips202Output::new(
            scratch.0.get_mut(..output.len()).ok_or(Error::Length)?,
            last,
        )
        .map_err(|_| Error::Bits)?;
        let value = match core::mem::replace(self, Self::Empty) {
            Self::A(s) => s.finalize_secret_bits(input, staging),
            Self::B(s) => s.finalize_secret_bits(input, staging),
            _ => return Err(Error::State),
        }
        .map_err(|_| Error::Crypto)?;
        copy_secret_region(output, value.expose()).map_err(|_| Error::Copy)
    }
    pub(super) fn finish_xof(&mut self, input: Fips202BitString<'_>) -> Result<(), Error> {
        *self = match core::mem::replace(self, Self::Empty) {
            Self::X(s) => Self::R(s.finalize_bits_xof(input).map_err(|_| Error::Crypto)?),
            Self::Y(s) => Self::S(s.finalize_bits_xof(input).map_err(|_| Error::Crypto)?),
            _ => return Err(Error::State),
        };
        Ok(())
    }
    pub(super) fn squeeze(
        &mut self,
        output: &mut [u8],
        last: u8,
        terminal: bool,
    ) -> Result<(), Error> {
        let mut scratch = Scratch([0; 1024]);
        let stage = scratch.0.get_mut(..output.len()).ok_or(Error::Length)?;
        if terminal {
            let bits = Fips202Output::new(stage, last).map_err(|_| Error::Bits)?;
            let result = match core::mem::replace(self, Self::Empty) {
                Self::R(s) => s.squeeze_final_bits_secret(bits),
                Self::S(s) => s.squeeze_final_bits_secret(bits),
                _ => return Err(Error::State),
            }
            .map_err(|_| Error::Crypto)?;
            copy_secret_region(output, result.expose()).map_err(|_| Error::Copy)
        } else {
            let result = match self {
                Self::R(s) => s.squeeze_secret(stage),
                Self::S(s) => s.squeeze_secret(stage),
                _ => return Err(Error::State),
            }
            .map_err(|_| Error::Crypto)?;
            copy_secret_region(output, result.expose()).map_err(|_| Error::Copy)
        }
    }
}
