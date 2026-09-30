use super::{Domain, Prepared};
use crate::{Fips202BitString, KmacError, backend::CshakeState};
use brynja_core::{clear_owned_region, xor_secret_byte_bits};
use brynja_hash_sha3::left_encode_u128;
use core::marker::PhantomData;
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Custom,
    Key,
    Dead,
}
pub(super) struct Setup<D: Domain> {
    domain: D,
    state: D::State,
    pending: [u8; 1],
    used: u8,
    remaining: u128,
    key_bits: u128,
    emitted: u128,
    expected: u128,
    phase: Phase,
    thread_bound: PhantomData<*mut ()>,
}
struct Operation<'a, D: Domain> {
    setup: &'a mut Setup<D>,
    complete: bool,
}
impl<D: Domain> Drop for Operation<'_, D> {
    fn drop(&mut self) {
        if !self.complete {
            self.setup.wipe();
        }
    }
}
impl<D: Domain> Setup<D> {
    pub(super) fn new(key_bits: u128, custom_bits: u128) -> Result<Self, KmacError> {
        if key_bits < D::STRENGTH {
            return Err(KmacError::KeyTooShort);
        }
        let rate = u128::try_from(D::RATE).map_err(|_| KmacError::MessageTooLong)?;
        if !matches!(D::RATE, 136 | 168) {
            return Err(KmacError::StateConsumed);
        }
        let prefix = left_encode_u128(rate)
            .as_bytes()
            .len()
            .checked_add(left_encode_u128(key_bits).as_bytes().len())
            .ok_or(KmacError::MessageTooLong)?;
        let bytes = key_bits
            .checked_div(8)
            .and_then(|n| n.checked_add(u128::from(!key_bits.is_multiple_of(8))))
            .and_then(|n| n.checked_add(u128::try_from(prefix).ok()?))
            .ok_or(KmacError::MessageTooLong)?;
        let remainder = bytes.checked_rem(rate).ok_or(KmacError::MessageTooLong)?;
        let expected = bytes
            .checked_add(if remainder == 0 {
                0
            } else {
                rate.checked_sub(remainder)
                    .ok_or(KmacError::MessageTooLong)?
            })
            .ok_or(KmacError::MessageTooLong)?;
        Ok(Self {
            domain: D::new(custom_bits)?,
            state: D::State::new_kmac(
                Fips202BitString::new(&[], 0).map_err(|_| KmacError::InvalidBitString)?,
            )?,
            pending: [0],
            used: 0,
            remaining: custom_bits,
            key_bits,
            emitted: 0,
            expected,
            phase: Phase::Custom,
            thread_bound: PhantomData,
        })
    }
    pub(super) fn custom(&mut self, input: Fips202BitString<'_>) -> Result<(), KmacError> {
        let mut op = Operation {
            setup: self,
            complete: false,
        };
        if op.setup.phase != Phase::Custom {
            return Err(KmacError::StateConsumed);
        }
        let bits = u128::try_from(input.bit_len()).map_err(|_| KmacError::MessageTooLong)?;
        let remaining = op
            .setup
            .remaining
            .checked_sub(bits)
            .ok_or(KmacError::MessageTooLong)?;
        // Empty completed S has no domain absorption step to perform.
        if bits != 0 {
            op.setup.domain.custom(input)?;
        }
        op.setup.remaining = remaining;
        op.complete = true;
        Ok(())
    }
    pub(super) fn finish_custom(&mut self) -> Result<(), KmacError> {
        let mut op = Operation {
            setup: self,
            complete: false,
        };
        if op.setup.phase != Phase::Custom || op.setup.remaining != 0 {
            return Err(KmacError::StateConsumed);
        }
        op.setup.state = op.setup.domain.finish()?;
        op.setup.bytes(
            left_encode_u128(u128::try_from(D::RATE).map_err(|_| KmacError::MessageTooLong)?)
                .as_bytes(),
        )?;
        op.setup
            .bytes(left_encode_u128(op.setup.key_bits).as_bytes())?;
        op.setup.remaining = op.setup.key_bits;
        op.setup.phase = Phase::Key;
        op.complete = true;
        Ok(())
    }
    pub(super) fn key(&mut self, input: Fips202BitString<'_>) -> Result<(), KmacError> {
        let mut op = Operation {
            setup: self,
            complete: false,
        };
        if op.setup.phase != Phase::Key {
            return Err(KmacError::StateConsumed);
        }
        let bits = u128::try_from(input.bit_len()).map_err(|_| KmacError::MessageTooLong)?;
        let remaining = op
            .setup
            .remaining
            .checked_sub(bits)
            .ok_or(KmacError::MessageTooLong)?;
        let complete = input.bit_len() / 8;
        op.setup.bytes(
            input
                .as_bytes()
                .get(..complete)
                .ok_or(KmacError::InvalidBitString)?,
        )?;
        let valid = input.valid_bits_in_last_byte();
        if (1..8).contains(&valid) {
            op.setup.bits(
                input
                    .as_bytes()
                    .get(complete)
                    .ok_or(KmacError::InvalidBitString)?,
                valid,
            )?;
        }
        op.setup.remaining = remaining;
        op.complete = true;
        Ok(())
    }
    fn bytes(&mut self, input: &[u8]) -> Result<(), KmacError> {
        if self.used == 0 {
            let emitted = self
                .emitted
                .checked_add(u128::try_from(input.len()).map_err(|_| KmacError::MessageTooLong)?)
                .ok_or(KmacError::MessageTooLong)?;
            self.state.update(input)?;
            self.emitted = emitted;
            return Ok(());
        }
        for byte in input {
            self.bits(byte, 8)?;
        }
        Ok(())
    }
    fn bits(&mut self, byte: &u8, valid: u8) -> Result<(), KmacError> {
        if !(1..=8).contains(&valid) || self.used >= 8 {
            return Err(KmacError::StateConsumed);
        }
        let mut position = 0_u8;
        while position < valid {
            let count = valid
                .checked_sub(position)
                .and_then(|n| 8_u8.checked_sub(self.used).map(|left| n.min(left)))
                .ok_or(KmacError::StateConsumed)?;
            xor_secret_byte_bits(&mut self.pending[0], byte, position, count, self.used)
                .map_err(|_| KmacError::SecretMemory)?;
            position = position
                .checked_add(count)
                .ok_or(KmacError::StateConsumed)?;
            self.used = self
                .used
                .checked_add(count)
                .ok_or(KmacError::StateConsumed)?;
            if self.used == 8 {
                self.flush()?;
            }
        }
        Ok(())
    }
    fn flush(&mut self) -> Result<(), KmacError> {
        let emitted = self
            .emitted
            .checked_add(1)
            .ok_or(KmacError::MessageTooLong)?;
        self.state.update(&self.pending)?;
        let _ = clear_owned_region(&mut self.pending).map_err(|_| KmacError::SecretMemory)?;
        self.emitted = emitted;
        self.used = 0;
        Ok(())
    }
    pub(super) fn finish(&mut self) -> Result<Prepared<D::State>, KmacError> {
        let mut op = Operation {
            setup: self,
            complete: false,
        };
        if op.setup.phase != Phase::Key || op.setup.remaining != 0 {
            return Err(KmacError::StateConsumed);
        }
        if op.setup.used != 0 {
            op.setup.flush()?;
        }
        let rate = u128::try_from(D::RATE).map_err(|_| KmacError::MessageTooLong)?;
        let remainder = op
            .setup
            .emitted
            .checked_rem(rate)
            .ok_or(KmacError::MessageTooLong)?;
        if remainder != 0 {
            let count = usize::try_from(
                rate.checked_sub(remainder)
                    .ok_or(KmacError::MessageTooLong)?,
            )
            .map_err(|_| KmacError::MessageTooLong)?;
            let zeros = [0; 168];
            op.setup
                .bytes(zeros.get(..count).ok_or(KmacError::StateConsumed)?)?;
        }
        if op.setup.used != 0 || op.setup.emitted != op.setup.expected {
            return Err(KmacError::StateConsumed);
        }
        let replacement = D::State::new_kmac(
            Fips202BitString::new(&[], 0).map_err(|_| KmacError::InvalidBitString)?,
        )?;
        let state = core::mem::replace(&mut op.setup.state, replacement);
        op.setup.wipe();
        op.complete = true;
        Ok(Prepared(state))
    }
    fn wipe(&mut self) {
        self.domain.wipe();
        self.state.wipe_in_place();
        let _ = clear_owned_region(&mut self.pending);
        self.used = 0;
        self.remaining = 0;
        self.key_bits = 0;
        self.emitted = 0;
        self.expected = 0;
        self.phase = Phase::Dead;
    }
}
impl<D: Domain> Drop for Setup<D> {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(test)]
mod tests;
