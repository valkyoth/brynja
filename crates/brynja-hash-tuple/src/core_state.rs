use brynja_core::clear_owned_region;
use brynja_hash_sha3::Fips202BitString;

use crate::{
    backend::{Backend, BackendReader, BackendStrength},
    error::TupleHashError,
    secret_encoding::SecretEncodedInteger,
};

pub(crate) struct TupleCore {
    backend: Backend,
    pending: [u8; 1],
    used: [u8; 1],
    items: [u8; 16],
    remaining: [u8; 16],
    failed: [u8; 1],
}

impl TupleCore {
    pub(crate) fn new(
        strength: BackendStrength,
        customization: Fips202BitString<'_>,
    ) -> Result<Self, TupleHashError> {
        Ok(Self {
            backend: Backend::new(strength, customization)?,
            pending: [0],
            used: [0],
            items: [0; 16],
            remaining: [0; 16],
            failed: [0],
        })
    }

    pub(crate) fn item_count(&self) -> u128 {
        read_u128(&self.items)
    }

    pub(crate) fn push_item(&mut self, item: Fips202BitString<'_>) -> Result<(), TupleHashError> {
        let bits = u128::try_from(item.bit_len()).map_err(|_| TupleHashError::MessageTooLong)?;
        self.begin_item(bits)?;
        self.push_bit_string(item)?;
        self.consume_item(bits)?;
        self.complete_item()
    }

    pub(crate) fn begin_item(&mut self, bits: u128) -> Result<(), TupleHashError> {
        self.ensure_live()?;
        let prefix = SecretEncodedInteger::left(bits)?;
        let prefix_bytes = prefix.as_bytes()?;
        let prefix_bits = u128::try_from(prefix_bytes.len())
            .ok()
            .and_then(|value| value.checked_mul(8))
            .ok_or(TupleHashError::MessageTooLong)?;
        let added = prefix_bits
            .checked_add(bits)
            .ok_or(TupleHashError::MessageTooLong)?;
        let pending = u128::from(self.used());
        self.backend.check_additional_bits(
            pending
                .checked_add(added)
                .ok_or(TupleHashError::MessageTooLong)?,
        )?;
        let count = self
            .item_count()
            .checked_add(1)
            .ok_or(TupleHashError::MessageTooLong)?;
        self.failed = [1];
        write_u128(&mut self.remaining, bits)?;
        self.push_bytes(prefix_bytes)?;
        write_u128(&mut self.items, count)?;
        Ok(())
    }

    pub(crate) fn item_remaining(&self) -> u128 {
        read_u128(&self.remaining)
    }

    pub(crate) fn check_item_fragment(&self, bits: u128) -> Result<(), TupleHashError> {
        checked_remaining_after(self.item_remaining(), bits).map(|_| ())
    }

    pub(crate) fn consume_item(&mut self, bits: u128) -> Result<(), TupleHashError> {
        let remaining = checked_remaining_after(self.item_remaining(), bits)?;
        write_u128(&mut self.remaining, remaining)?;
        Ok(())
    }

    pub(crate) fn complete_item(&mut self) -> Result<(), TupleHashError> {
        if self.item_remaining() != 0 {
            return Err(TupleHashError::IncompleteItem);
        }
        let _ = clear_owned_region(&mut self.remaining);
        let _ = clear_owned_region(&mut self.failed);
        Ok(())
    }

    pub(crate) fn push_bit_string(
        &mut self,
        input: Fips202BitString<'_>,
    ) -> Result<(), TupleHashError> {
        let bytes = input.as_bytes();
        let partial = if input.is_byte_aligned() {
            None
        } else {
            bytes
                .last()
                .copied()
                .map(|byte| (byte, input.valid_bits_in_last_byte()))
        };
        let complete_length = if partial.is_some() {
            bytes.len().saturating_sub(1)
        } else {
            bytes.len()
        };
        let complete = bytes
            .get(..complete_length)
            .ok_or(TupleHashError::InvalidBitString)?;
        self.push_bytes(complete)?;
        if let Some((byte, valid)) = partial {
            self.push_bits(byte, valid)?;
        }
        Ok(())
    }

    pub(crate) fn push_bytes(&mut self, input: &[u8]) -> Result<(), TupleHashError> {
        if self.used() == 0 {
            return self.backend.update(input).map_err(TupleHashError::from);
        }
        for byte in input {
            self.push_bits(*byte, 8)?;
        }
        Ok(())
    }

    fn push_bits(&mut self, byte: u8, valid: u8) -> Result<(), TupleHashError> {
        for position in 0..valid {
            let bit = (byte >> position) & 1;
            let used = self.used();
            let Some(pending) = self.pending.first_mut() else {
                return Err(TupleHashError::SecretMemory);
            };
            *pending |= bit << used;
            self.set_used(used.checked_add(1).ok_or(TupleHashError::MessageTooLong)?);
            if self.used() == 8 {
                self.flush()?;
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), TupleHashError> {
        self.backend.update(&self.pending)?;
        let _ = clear_owned_region(&mut self.pending);
        let _ = clear_owned_region(&mut self.used);
        Ok(())
    }

    pub(crate) fn finish_in_place(
        &mut self,
        output_bits: u128,
    ) -> Result<BackendReader<'_>, TupleHashError> {
        self.ensure_live()?;
        let suffix = SecretEncodedInteger::right(output_bits)?;
        let suffix_bytes = suffix.as_bytes()?;
        let suffix_bits = u128::try_from(suffix_bytes.len())
            .ok()
            .and_then(|value| value.checked_mul(8))
            .ok_or(TupleHashError::OutputTooLong)?;
        self.backend.check_additional_bits(
            u128::from(self.used())
                .checked_add(suffix_bits)
                .ok_or(TupleHashError::MessageTooLong)?,
        )?;
        self.push_bytes(suffix_bytes)?;
        let valid = self.used();
        let reader = if valid == 0 {
            self.backend.finalize_in_place(None)?
        } else {
            let tail = Fips202BitString::new(&self.pending, valid)
                .map_err(|_| TupleHashError::InvalidBitString)?;
            self.backend.finalize_in_place(Some(tail))?
        };
        let _ = clear_owned_region(&mut self.pending);
        let _ = clear_owned_region(&mut self.used);
        Ok(reader)
    }

    pub(crate) fn abandon_item(&mut self) {
        self.failed = [1];
        let _ = clear_owned_region(&mut self.remaining);
    }

    pub(crate) fn cancel_in_place(&mut self) {
        self.wipe();
    }

    fn ensure_live(&self) -> Result<(), TupleHashError> {
        if self.failed.first().copied().unwrap_or(1) == 0 {
            Ok(())
        } else {
            Err(TupleHashError::ItemAbandoned)
        }
    }

    fn used(&self) -> u8 {
        self.used.first().copied().unwrap_or_default()
    }

    fn set_used(&mut self, value: u8) {
        if let Some(used) = self.used.first_mut() {
            *used = value;
        }
    }

    #[inline(never)]
    fn wipe(&mut self) {
        self.backend.wipe();
        let _ = clear_owned_region(&mut self.pending);
        let _ = clear_owned_region(&mut self.used);
        let _ = clear_owned_region(&mut self.items);
        let _ = clear_owned_region(&mut self.remaining);
        let _ = clear_owned_region(&mut self.failed);
    }
}

impl Drop for TupleCore {
    fn drop(&mut self) {
        self.wipe();
    }
}

pub(crate) fn byte_string(input: &[u8]) -> Result<Fips202BitString<'_>, TupleHashError> {
    let valid = if input.is_empty() { 0 } else { 8 };
    Fips202BitString::new(input, valid).map_err(|_| TupleHashError::InvalidBitString)
}

pub(crate) fn output_bits(length: usize) -> Result<u128, TupleHashError> {
    u128::try_from(length)
        .ok()
        .and_then(|value| value.checked_mul(8))
        .ok_or(TupleHashError::OutputTooLong)
}

pub(crate) fn checked_remaining_after(remaining: u128, bits: u128) -> Result<u128, TupleHashError> {
    remaining
        .checked_sub(bits)
        .ok_or(TupleHashError::MessageTooLong)
}

fn read_u128(bytes: &[u8; 16]) -> u128 {
    let mut value = 0_u128;
    for (index, byte) in bytes.iter().enumerate() {
        let shift = index.saturating_mul(8);
        value |= u128::from(*byte) << shift;
    }
    value
}

fn write_u128(bytes: &mut [u8; 16], value: u128) -> Result<(), TupleHashError> {
    for (index, byte) in bytes.iter_mut().enumerate() {
        let shift = index.saturating_mul(8);
        *byte = u8::try_from((value >> shift) & u128::from(u8::MAX))
            .map_err(|_| TupleHashError::MessageTooLong)?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod assurance_contract {
    use brynja_hash_sha3::Fips202BitString;

    use super::{BackendStrength, TupleCore};

    #[test]
    fn registered_algorithm_tuplehash_owner_contract_is_compiler_checked() {
        let customization = Fips202BitString::new(&[], 0);
        assert!(customization.is_ok());
        let Ok(customization) = customization else {
            return;
        };
        let owner = TupleCore::new(BackendStrength::Bits128, customization);
        assert!(owner.is_ok());
        let Ok(mut owner) = owner else {
            return;
        };
        owner.pending.fill(0xa5);
        owner.used.fill(0x05);
        owner.items.fill(0x5a);
        owner.remaining.fill(0x3c);
        owner.failed.fill(0x01);
        owner.wipe();
        assert!(owner.pending.iter().all(|byte| *byte == 0));
        assert!(owner.used.iter().all(|byte| *byte == 0));
        assert!(owner.items.iter().all(|byte| *byte == 0));
        assert!(owner.remaining.iter().all(|byte| *byte == 0));
        assert!(owner.failed.iter().all(|byte| *byte == 0));
    }
}
