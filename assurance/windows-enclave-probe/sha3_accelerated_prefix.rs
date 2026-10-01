//! Exact-length streamed SP 800-185 prefix for the enclave's AVX2 state adapter.
//! Prefix lengths are declared public; pending fractional content is secret.
use super::{Error, Fips202BitString, engine::Engine};
use brynja_core::{clear_owned_region, xor_secret_byte_bits};
use brynja_hash_sha3::left_encode_u128;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Name,
    Custom,
    Complete,
}
pub(super) struct Prefix {
    pending: [u8; 1],
    used: u8,
    remaining: u128,
    custom: u128,
    emitted: u128,
    expected: u128,
    rate: usize,
    phase: Phase,
}
impl Prefix {
    pub(super) fn new(
        engine: &mut Engine<'_>,
        rate: usize,
        name: u128,
        custom: u128,
    ) -> Result<Self, Error> {
        if !matches!(rate, 136 | 168) {
            return Err(Error::PrefixEncoding);
        }
        let r = u128::try_from(rate).map_err(|_| Error::LengthOverflow)?;
        let fixed = left_encode_u128(r)
            .as_bytes()
            .len()
            .checked_add(left_encode_u128(name).as_bytes().len())
            .and_then(|n| n.checked_add(left_encode_u128(custom).as_bytes().len()))
            .ok_or(Error::LengthOverflow)?;
        let bits = u128::try_from(fixed)
            .map_err(|_| Error::LengthOverflow)?
            .checked_mul(8)
            .and_then(|n| n.checked_add(name))
            .and_then(|n| n.checked_add(custom))
            .ok_or(Error::LengthOverflow)?;
        let bytes = bits
            .checked_div(8)
            .and_then(|n| n.checked_add(u128::from(bits % 8 != 0)))
            .ok_or(Error::LengthOverflow)?;
        let rest = bytes.checked_rem(r).ok_or(Error::LengthOverflow)?;
        let expected = bytes
            .checked_add(if rest == 0 {
                0
            } else {
                r.checked_sub(rest).ok_or(Error::LengthOverflow)?
            })
            .ok_or(Error::LengthOverflow)?;
        let customized = name != 0 || custom != 0;
        let mut p = Self {
            pending: [0],
            used: 0,
            remaining: name,
            custom,
            emitted: 0,
            expected: if customized { expected } else { 0 },
            rate,
            phase: if customized {
                Phase::Name
            } else {
                Phase::Complete
            },
        };
        if customized {
            p.bytes(engine, left_encode_u128(r).as_bytes())?;
            p.bytes(engine, left_encode_u128(name).as_bytes())?;
            p.advance(engine)?;
        }
        Ok(p)
    }
    pub(super) fn push(
        &mut self,
        engine: &mut Engine<'_>,
        name: bool,
        input: Fips202BitString<'_>,
    ) -> Result<(), Error> {
        if self.phase != if name { Phase::Name } else { Phase::Custom } {
            return Err(Error::Terminal);
        }
        let bits = u128::try_from(input.bit_len()).map_err(|_| Error::LengthOverflow)?;
        let remaining = self
            .remaining
            .checked_sub(bits)
            .ok_or(Error::PrefixEncoding)?;
        let whole = input.bit_len() / 8;
        self.bytes(
            engine,
            input.as_bytes().get(..whole).ok_or(Error::Terminal)?,
        )?;
        let valid = input.valid_bits_in_last_byte();
        if (1..8).contains(&valid) {
            self.bits(
                engine,
                input.as_bytes().get(whole).ok_or(Error::Terminal)?,
                valid,
            )?;
        }
        self.remaining = remaining;
        self.advance(engine)
    }
    fn advance(&mut self, engine: &mut Engine<'_>) -> Result<(), Error> {
        if self.remaining != 0 {
            return Ok(());
        }
        if self.phase == Phase::Name {
            self.bytes(engine, left_encode_u128(self.custom).as_bytes())?;
            self.remaining = self.custom;
            self.phase = Phase::Custom;
        }
        if self.phase == Phase::Custom && self.remaining == 0 {
            if self.used != 0 {
                self.flush(engine)?;
            }
            let r = u128::try_from(self.rate).map_err(|_| Error::LengthOverflow)?;
            let rest = self.emitted.checked_rem(r).ok_or(Error::LengthOverflow)?;
            if rest != 0 {
                let count = usize::try_from(r.checked_sub(rest).ok_or(Error::LengthOverflow)?)
                    .map_err(|_| Error::LengthOverflow)?;
                self.bytes(engine, [0; 168].get(..count).ok_or(Error::Terminal)?)?;
            }
            if self.emitted != self.expected {
                return Err(Error::Terminal);
            }
            self.phase = Phase::Complete;
        }
        Ok(())
    }
    fn bytes(&mut self, engine: &mut Engine<'_>, input: &[u8]) -> Result<(), Error> {
        if self.used == 0 {
            let count = u128::try_from(input.len()).map_err(|_| Error::LengthOverflow)?;
            let next = self
                .emitted
                .checked_add(count)
                .ok_or(Error::LengthOverflow)?;
            engine.update(input)?;
            self.emitted = next;
        } else {
            for byte in input {
                self.bits(engine, byte, 8)?;
            }
        }
        Ok(())
    }
    fn bits(&mut self, engine: &mut Engine<'_>, byte: &u8, valid: u8) -> Result<(), Error> {
        if !(1..=8).contains(&valid) || self.used >= 8 {
            return Err(Error::Terminal);
        }
        let mut position = 0_u8;
        while position < valid {
            let count = valid
                .checked_sub(position)
                .and_then(|v| 8_u8.checked_sub(self.used).map(|left| v.min(left)))
                .ok_or(Error::Terminal)?;
            xor_secret_byte_bits(&mut self.pending[0], byte, position, count, self.used)
                .map_err(|_| Error::SecretMemory)?;
            position = position.checked_add(count).ok_or(Error::Terminal)?;
            self.used = self.used.checked_add(count).ok_or(Error::Terminal)?;
            if self.used == 8 {
                self.flush(engine)?;
            }
        }
        Ok(())
    }
    fn flush(&mut self, engine: &mut Engine<'_>) -> Result<(), Error> {
        let next = self.emitted.checked_add(1).ok_or(Error::LengthOverflow)?;
        engine.update(&self.pending)?;
        let _ = clear_owned_region(&mut self.pending).map_err(|_| Error::SecretMemory)?;
        self.emitted = next;
        self.used = 0;
        Ok(())
    }
    pub(super) fn complete(&self) -> Result<(), Error> {
        if self.phase != Phase::Complete
            || self.remaining != 0
            || self.used != 0
            || self.emitted != self.expected
        {
            return Err(Error::Terminal);
        }
        Ok(())
    }
}
impl Drop for Prefix {
    fn drop(&mut self) {
        let _ = clear_owned_region(&mut self.pending);
        self.used = 0;
        self.remaining = 0;
        self.custom = 0;
        self.emitted = 0;
        self.expected = 0;
    }
}

#[cfg(test)]
#[path = "sha3_accelerated_prefix_tests.rs"]
mod tests;
