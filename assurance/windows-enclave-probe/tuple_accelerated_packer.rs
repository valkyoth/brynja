//! Clearing bit packer shared byte-for-byte with scalar TupleHash, except state lifetime.
use super::{Bits, Error, State};
use brynja_core::{clear_owned_region, xor_secret_byte_bits};

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
    pub(super) fn append(&mut self, state: &mut State<'_>, input: Bits<'_>) -> Result<(), Error> {
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
    fn bits(&mut self, state: &mut State<'_>, byte: &u8, valid: u8) -> Result<(), Error> {
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
    pub(super) fn finish(&mut self, state: &mut State<'_>) -> Result<(), Error> {
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
