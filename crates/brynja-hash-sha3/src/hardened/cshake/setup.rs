//! Incremental, exact-length SP 800-185 setup. No incomplete setup can become
//! an absorbing message state. The single pending byte is an owned secret.
use super::{CshakeLifecycle, HardenedCshake128, HardenedCshake256, HardenedSha3Error};
use crate::{Fips202BitString, hardened::owner::HardenedFips202Owner, left_encode_u128};
use brynja_core::{clear_owned_region, xor_secret_byte_bits};
use core::marker::PhantomData;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Name,
    Custom,
    Complete,
    Dead,
}
struct Setup<const RATE: usize> {
    owner: Option<HardenedFips202Owner<RATE>>,
    pending: [u8; 1],
    used: u8,
    emitted: u128,
    remaining: u128,
    custom_bits: u128,
    expected: u128,
    phase: Phase,
    customized: bool,
    thread_bound: PhantomData<*mut ()>,
}
struct Operation<'a, const RATE: usize> {
    setup: &'a mut Setup<RATE>,
    complete: bool,
}
impl<const RATE: usize> Drop for Operation<'_, RATE> {
    fn drop(&mut self) {
        if !self.complete {
            self.setup.wipe();
        }
    }
}
impl<const RATE: usize> Setup<RATE> {
    fn new(name_bits: u128, custom_bits: u128) -> Result<Self, HardenedSha3Error> {
        let invalid = HardenedSha3Error::MessageTooLong;
        let rate = u128::try_from(RATE).map_err(|_| invalid)?;
        if !matches!(RATE, 136 | 168) {
            return Err(invalid);
        }
        let customized = name_bits != 0 || custom_bits != 0;
        let fixed = left_encode_u128(rate)
            .as_bytes()
            .len()
            .checked_add(left_encode_u128(name_bits).as_bytes().len())
            .and_then(|n| n.checked_add(left_encode_u128(custom_bits).as_bytes().len()))
            .ok_or(invalid)?;
        let bits = u128::try_from(fixed)
            .map_err(|_| invalid)?
            .checked_mul(8)
            .and_then(|n| n.checked_add(name_bits))
            .and_then(|n| n.checked_add(custom_bits))
            .ok_or(invalid)?;
        let bytes = bits
            .checked_div(8)
            .and_then(|n| n.checked_add(u128::from(bits % 8 != 0)))
            .ok_or(invalid)?;
        let remainder = bytes.checked_rem(rate).ok_or(invalid)?;
        let expected = bytes
            .checked_add(if remainder == 0 {
                0
            } else {
                rate.checked_sub(remainder).ok_or(invalid)?
            })
            .ok_or(invalid)?;
        let mut setup = Self {
            owner: Some(HardenedFips202Owner::new()),
            pending: [0],
            used: 0,
            emitted: 0,
            remaining: name_bits,
            custom_bits,
            expected: if customized { expected } else { 0 },
            phase: if customized {
                Phase::Name
            } else {
                Phase::Complete
            },
            customized,
            thread_bound: PhantomData,
        };
        if customized {
            setup.bytes(left_encode_u128(rate).as_bytes())?;
            setup.bytes(left_encode_u128(name_bits).as_bytes())?;
            setup.advance()?;
        }
        Ok(setup)
    }
    fn push(&mut self, phase: Phase, input: Fips202BitString<'_>) -> Result<(), HardenedSha3Error> {
        let mut op = Operation {
            setup: self,
            complete: false,
        };
        if op.setup.phase != phase {
            return Err(HardenedSha3Error::StateConsumed);
        }
        let bits =
            u128::try_from(input.bit_len()).map_err(|_| HardenedSha3Error::MessageTooLong)?;
        let remaining = op
            .setup
            .remaining
            .checked_sub(bits)
            .ok_or(HardenedSha3Error::MessageTooLong)?;
        let complete = input.bit_len() / 8;
        op.setup.bytes(
            input
                .as_bytes()
                .get(..complete)
                .ok_or(HardenedSha3Error::StateConsumed)?,
        )?;
        let valid = input.valid_bits_in_last_byte();
        if (1..8).contains(&valid) {
            op.setup.bits(
                input
                    .as_bytes()
                    .get(complete)
                    .ok_or(HardenedSha3Error::StateConsumed)?,
                valid,
            )?;
        }
        op.setup.remaining = remaining;
        op.setup.advance()?;
        op.complete = true;
        Ok(())
    }
    fn advance(&mut self) -> Result<(), HardenedSha3Error> {
        if self.remaining != 0 {
            return Ok(());
        }
        if self.phase == Phase::Name {
            self.bytes(left_encode_u128(self.custom_bits).as_bytes())?;
            self.remaining = self.custom_bits;
            self.phase = Phase::Custom;
        }
        if self.phase == Phase::Custom && self.remaining == 0 {
            if self.used != 0 {
                self.flush()?;
            }
            let rate = u128::try_from(RATE).map_err(|_| HardenedSha3Error::MessageTooLong)?;
            let remainder = self
                .emitted
                .checked_rem(rate)
                .ok_or(HardenedSha3Error::MessageTooLong)?;
            if remainder != 0 {
                let count = usize::try_from(
                    rate.checked_sub(remainder)
                        .ok_or(HardenedSha3Error::MessageTooLong)?,
                )
                .map_err(|_| HardenedSha3Error::MessageTooLong)?;
                let zeros = [0; 168];
                self.bytes(zeros.get(..count).ok_or(HardenedSha3Error::StateConsumed)?)?;
            }
            if self.emitted != self.expected {
                return Err(HardenedSha3Error::StateConsumed);
            }
            self.phase = Phase::Complete;
        }
        Ok(())
    }
    fn bytes(&mut self, bytes: &[u8]) -> Result<(), HardenedSha3Error> {
        if self.used == 0 {
            let count =
                u128::try_from(bytes.len()).map_err(|_| HardenedSha3Error::MessageTooLong)?;
            let emitted = self
                .emitted
                .checked_add(count)
                .ok_or(HardenedSha3Error::MessageTooLong)?;
            self.owner
                .as_mut()
                .ok_or(HardenedSha3Error::StateConsumed)?
                .update(bytes)
                .map_err(|()| HardenedSha3Error::MessageTooLong)?;
            self.emitted = emitted;
            return Ok(());
        }
        for byte in bytes {
            self.bits(byte, 8)?;
        }
        Ok(())
    }
    fn bits(&mut self, byte: &u8, valid: u8) -> Result<(), HardenedSha3Error> {
        if !(1..=8).contains(&valid) || self.used >= 8 {
            return Err(HardenedSha3Error::StateConsumed);
        }
        let mut position = 0_u8;
        while position < valid {
            let count = valid
                .checked_sub(position)
                .and_then(|v| 8_u8.checked_sub(self.used).map(|left| v.min(left)))
                .ok_or(HardenedSha3Error::StateConsumed)?;
            xor_secret_byte_bits(&mut self.pending[0], byte, position, count, self.used)
                .map_err(|_| HardenedSha3Error::StateConsumed)?;
            position = position
                .checked_add(count)
                .ok_or(HardenedSha3Error::StateConsumed)?;
            self.used = self
                .used
                .checked_add(count)
                .ok_or(HardenedSha3Error::StateConsumed)?;
            if self.used == 8 {
                self.flush()?;
            }
        }
        Ok(())
    }
    fn flush(&mut self) -> Result<(), HardenedSha3Error> {
        let emitted = self
            .emitted
            .checked_add(1)
            .ok_or(HardenedSha3Error::MessageTooLong)?;
        self.owner
            .as_mut()
            .ok_or(HardenedSha3Error::StateConsumed)?
            .update(&self.pending)
            .map_err(|()| HardenedSha3Error::MessageTooLong)?;
        let _ = clear_owned_region(&mut self.pending)?;
        self.emitted = emitted;
        self.used = 0;
        Ok(())
    }
    fn finish(mut self) -> Result<HardenedFips202Owner<RATE>, HardenedSha3Error> {
        self.finish_erasing_source()
    }
    fn finish_erasing_source(&mut self) -> Result<HardenedFips202Owner<RATE>, HardenedSha3Error> {
        let mut op = Operation {
            setup: self,
            complete: false,
        };
        if op.setup.phase != Phase::Complete
            || op.setup.remaining != 0
            || op.setup.used != 0
            || op.setup.emitted != op.setup.expected
        {
            return Err(HardenedSha3Error::StateConsumed);
        }
        let source = op
            .setup
            .owner
            .as_mut()
            .ok_or(HardenedSha3Error::StateConsumed)?;
        let mut owner = core::mem::replace(source, HardenedFips202Owner::new());
        source.wipe();
        owner.remember_cshake_setup(op.setup.customized);
        op.setup.wipe();
        op.complete = true;
        Ok(owner)
    }
    fn wipe(&mut self) {
        if let Some(owner) = self.owner.as_mut() {
            owner.wipe();
        }
        self.owner = None;
        let _ = clear_owned_region(&mut self.pending);
        self.phase = Phase::Dead;
        self.used = 0;
        self.emitted = 0;
        self.remaining = 0;
        self.custom_bits = 0;
        self.expected = 0;
        self.customized = false;
    }
}
impl<const RATE: usize> Drop for Setup<RATE> {
    fn drop(&mut self) {
        self.wipe();
    }
}

macro_rules! setup {
    ($setup:ident,$state:ident,$rate:literal) => {
        /// Incremental secret-bearing cSHAKE domain setup with public, exact N/S
        /// bit lengths. Storage is fixed-size; caller chunks need not be retained.
        /// A wrong phase, excess input or error clears and terminates the setup.
        /// Dropping clears owned memory; caller buffers/copies and fatal aborts
        /// remain outside this guarantee. Empty sections are skipped automatically.
        /// This object is neither Send, Sync, Copy, Clone nor Debug.
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_sha3::", stringify!($setup), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_sha3::", stringify!($setup), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_sha3::", stringify!($setup), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_sha3::", stringify!($setup), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_sha3::", stringify!($setup), ">();\n```")]
        pub struct $setup(Setup<$rate>);
        impl $setup {
            /// Declare the complete public lengths before absorbing any contents.
            pub fn new(
                name_bits: u128,
                customization_bits: u128,
            ) -> Result<Self, HardenedSha3Error> {
                Setup::new(name_bits, customization_bits).map(Self)
            }
            /// Absorb the next canonical low-bit-first N fragment. Fragments may
            /// end between bytes; their bits are concatenated without padding.
            pub fn name(&mut self, input: Fips202BitString<'_>) -> Result<(), HardenedSha3Error> {
                self.0.push(Phase::Name, input)
            }
            /// Absorb S only after the exact declared N length has arrived.
            pub fn customization(
                &mut self,
                input: Fips202BitString<'_>,
            ) -> Result<(), HardenedSha3Error> {
                self.0.push(Phase::Custom, input)
            }
            /// Consume setup; only exact complete N/S yields a usable state.
            pub fn finish(self) -> Result<$state, HardenedSha3Error> {
                Ok($state {
                    owner: self.0.finish()?,
                    lifecycle: CshakeLifecycle::Absorbing,
                })
            }
            /// Transfer completed setup while clearing this exact source object.
            /// Success or error terminates setup; no incomplete state is returned.
            pub fn finish_erasing_source(&mut self) -> Result<$state, HardenedSha3Error> {
                Ok($state {
                    owner: self.0.finish_erasing_source()?,
                    lifecycle: CshakeLifecycle::Absorbing,
                })
            }
            /// Clear this exact setup storage and permanently terminate it.
            pub fn wipe_in_place(&mut self) { self.0.wipe(); }
            /// Destroy incomplete or complete setup without beginning a message.
            pub fn cancel(self) {}
        }
    };
}
setup!(HardenedCshake128Setup, HardenedCshake128, 168);
setup!(HardenedCshake256Setup, HardenedCshake256, 136);

#[cfg(test)]
mod tests;
