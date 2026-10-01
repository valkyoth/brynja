//! Incremental bytepad(encode_string(K), rate), with exact completion.
use super::{Error, Fips202BitString};
use brynja_core::{clear_owned_region, xor_secret_byte_bits};
use brynja_hash_sha3::left_encode_u128;
use sha3_accelerated_state::State;

pub(super) struct Key {
    pending: [u8; 1],
    used: u8,
    remaining: u128,
    emitted: u128,
    expected: u128,
    rate: usize,
}
impl Key {
    pub(super) fn new(state: &mut State<'_>, bits: u128, rate: usize) -> Result<Self, Error> {
        let r = u128::try_from(rate).map_err(|_| Error::Length)?;
        if !matches!(rate, 136 | 168) {
            return Err(Error::Length);
        }
        let header = left_encode_u128(r)
            .as_bytes()
            .len()
            .checked_add(left_encode_u128(bits).as_bytes().len())
            .ok_or(Error::Length)?;
        let bytes = bits
            .checked_div(8)
            .and_then(|n| n.checked_add(u128::from(bits % 8 != 0)))
            .and_then(|n| n.checked_add(u128::try_from(header).ok()?))
            .ok_or(Error::Length)?;
        let rest = bytes.checked_rem(r).ok_or(Error::Length)?;
        let expected = bytes
            .checked_add(if rest == 0 {
                0
            } else {
                r.checked_sub(rest).ok_or(Error::Length)?
            })
            .ok_or(Error::Length)?;
        let mut key = Self {
            pending: [0],
            used: 0,
            remaining: bits,
            emitted: 0,
            expected,
            rate,
        };
        key.bytes(state, left_encode_u128(r).as_bytes())?;
        key.bytes(state, left_encode_u128(bits).as_bytes())?;
        Ok(key)
    }
    pub(super) fn push(
        &mut self,
        state: &mut State<'_>,
        bits: Fips202BitString<'_>,
    ) -> Result<(), Error> {
        let remaining = self
            .remaining
            .checked_sub(u128::try_from(bits.bit_len()).map_err(|_| Error::Length)?)
            .ok_or(Error::Length)?;
        let complete = bits.bit_len() / 8;
        self.bytes(state, bits.as_bytes().get(..complete).ok_or(Error::Bits)?)?;
        let last = bits.valid_bits_in_last_byte();
        if (1..8).contains(&last) {
            self.bits(
                state,
                bits.as_bytes().get(complete).ok_or(Error::Bits)?,
                last,
            )?;
        }
        self.remaining = remaining;
        Ok(())
    }
    fn bytes(&mut self, state: &mut State<'_>, input: &[u8]) -> Result<(), Error> {
        if self.used == 0 {
            let next = self
                .emitted
                .checked_add(u128::try_from(input.len()).map_err(|_| Error::Length)?)
                .ok_or(Error::Length)?;
            state.update(input).map_err(|_| Error::Crypto)?;
            self.emitted = next;
        } else {
            for byte in input {
                self.bits(state, byte, 8)?;
            }
        }
        Ok(())
    }
    fn bits(&mut self, state: &mut State<'_>, byte: &u8, valid: u8) -> Result<(), Error> {
        if !(1..=8).contains(&valid) || self.used >= 8 {
            return Err(Error::Bits);
        }
        let mut position = 0_u8;
        while position < valid {
            let count = valid
                .checked_sub(position)
                .and_then(|n| 8_u8.checked_sub(self.used).map(|left| n.min(left)))
                .ok_or(Error::Bits)?;
            xor_secret_byte_bits(&mut self.pending[0], byte, position, count, self.used)
                .map_err(|_| Error::Crypto)?;
            self.used = self.used.checked_add(count).ok_or(Error::Bits)?;
            position = position.checked_add(count).ok_or(Error::Bits)?;
            if self.used == 8 {
                self.flush(state)?;
            }
        }
        Ok(())
    }
    fn flush(&mut self, state: &mut State<'_>) -> Result<(), Error> {
        let next = self.emitted.checked_add(1).ok_or(Error::Length)?;
        state.update(&self.pending).map_err(|_| Error::Crypto)?;
        let _ = clear_owned_region(&mut self.pending).map_err(|_| Error::Crypto)?;
        self.used = 0;
        self.emitted = next;
        Ok(())
    }
    pub(super) fn finish(&mut self, state: &mut State<'_>) -> Result<(), Error> {
        if self.remaining != 0 {
            return Err(Error::State);
        }
        if self.used != 0 {
            self.flush(state)?;
        }
        let rate = u128::try_from(self.rate).map_err(|_| Error::Length)?;
        let rest = self.emitted.checked_rem(rate).ok_or(Error::Length)?;
        if rest != 0 {
            let count = usize::try_from(rate.checked_sub(rest).ok_or(Error::Length)?)
                .map_err(|_| Error::Length)?;
            self.bytes(state, [0; 168].get(..count).ok_or(Error::Length)?)?;
        }
        if self.used != 0 || self.emitted != self.expected {
            return Err(Error::State);
        }
        Ok(())
    }
}
impl Drop for Key {
    fn drop(&mut self) {
        let _ = clear_owned_region(&mut self.pending);
        self.used = 0;
        self.remaining = 0;
        self.emitted = 0;
        self.expected = 0;
    }
}
