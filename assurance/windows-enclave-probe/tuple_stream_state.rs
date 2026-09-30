//! Hardened cSHAKE and a clearing bit packer; no ordinary hash state.
use super::{Error, shape};
use brynja_core::{clear_owned_region, copy_secret_region, xor_secret_byte_bits};
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
    pub(super) fn setup(identity: u64, bits: u128) -> Result<Self, Error> {
        let name = Bits::new(b"TupleHash", 8).map_err(|_| Error::Bits)?;
        match identity {
            1 | 3 => {
                let mut s = HardenedCshake128Setup::new(72, bits).map_err(|_| Error::Crypto)?;
                s.name(name).map_err(|_| Error::Crypto)?;
                Ok(Self::Setup128(s))
            }
            2 | 4 => {
                let mut s = HardenedCshake256Setup::new(72, bits).map_err(|_| Error::Crypto)?;
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
    fn update(&mut self, input: &[u8]) -> Result<(), Error> {
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

pub(super) struct Packer {
    pending: [u8; 1],
    used: u8,
}
impl Packer {
    pub(super) const fn new() -> Self {
        Self {
            pending: [0],
            used: 0,
        }
    }
    pub(super) fn clear(&mut self) {
        let _ = clear_owned_region(&mut self.pending);
        self.used = 0;
    }
    pub(super) fn append(&mut self, state: &mut State, input: Bits<'_>) -> Result<(), Error> {
        // Bulk aligned prefixes never take the per-bit path.
        if self.used == 0 {
            let complete = input.bit_len() / 8;
            state.update(input.as_bytes().get(..complete).ok_or(Error::Length)?)?;
            if !input.is_byte_aligned() {
                self.bits(
                    state,
                    input.as_bytes().last().ok_or(Error::Bits)?,
                    input.valid_bits_in_last_byte(),
                )?;
            }
        } else {
            for (index, byte) in input.as_bytes().iter().enumerate() {
                let last = index.checked_add(1).ok_or(Error::Length)? == input.as_bytes().len();
                self.bits(
                    state,
                    byte,
                    if last {
                        input.valid_bits_in_last_byte()
                    } else {
                        8
                    },
                )?;
            }
        }
        Ok(())
    }
    fn bits(&mut self, state: &mut State, byte: &u8, valid: u8) -> Result<(), Error> {
        for bit in 0..valid {
            if self.used >= 8 {
                return Err(Error::Bits);
            }
            xor_secret_byte_bits(&mut self.pending[0], byte, bit, 1, self.used)
                .map_err(|_| Error::Bits)?;
            self.used = self.used.checked_add(1).ok_or(Error::Length)?;
            if self.used == 8 {
                state.update(&self.pending)?;
                self.clear();
            }
        }
        Ok(())
    }
    pub(super) fn finish(&mut self, state: &mut State) -> Result<(), Error> {
        let tail = if self.used == 0 {
            Bits::new(&[], 0)
        } else {
            Bits::new(&self.pending, self.used)
        }
        .map_err(|_| Error::Bits)?;
        state.finish(tail)?;
        self.clear();
        Ok(())
    }
}
impl Drop for Packer {
    fn drop(&mut self) {
        self.clear();
    }
}
