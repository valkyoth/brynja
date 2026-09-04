use brynja_core::clear_owned_region;
use brynja_hash_sha3::{Fips202BitString, left_encode_u128, right_encode_u128};

use crate::{
    backend::{Backend, BackendReader},
    error::TupleHashError,
};

pub(crate) struct TupleCore {
    backend: Backend,
    pending: [u8; 1],
    used: [u8; 1],
    items: [u8; 16],
    failed: [u8; 1],
}

impl TupleCore {
    pub(crate) fn new(
        strength: u16,
        customization: Fips202BitString<'_>,
    ) -> Result<Self, TupleHashError> {
        Ok(Self {
            backend: Backend::new(strength, customization)?,
            pending: [0],
            used: [0],
            items: [0; 16],
            failed: [0],
        })
    }

    pub(crate) fn item_count(&self) -> u128 {
        u128::from_le_bytes(self.items)
    }

    pub(crate) fn push_item(&mut self, item: Fips202BitString<'_>) -> Result<(), TupleHashError> {
        let bits = u128::try_from(item.bit_len()).map_err(|_| TupleHashError::MessageTooLong)?;
        self.begin_item(bits)?;
        self.push_bit_string(item)?;
        Ok(())
    }

    pub(crate) fn begin_item(&mut self, bits: u128) -> Result<(), TupleHashError> {
        self.ensure_live()?;
        let prefix = left_encode_u128(bits);
        let prefix_bits = u128::try_from(prefix.as_bytes().len())
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
        self.push_bytes(prefix.as_bytes())?;
        self.items.copy_from_slice(&count.to_le_bytes());
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

    pub(crate) fn finish(&mut self, output_bits: u128) -> Result<BackendReader, TupleHashError> {
        self.ensure_live()?;
        let suffix = right_encode_u128(output_bits);
        let suffix_bits = u128::try_from(suffix.as_bytes().len())
            .ok()
            .and_then(|value| value.checked_mul(8))
            .ok_or(TupleHashError::OutputTooLong)?;
        self.backend.check_additional_bits(
            u128::from(self.used())
                .checked_add(suffix_bits)
                .ok_or(TupleHashError::MessageTooLong)?,
        )?;
        self.push_bytes(suffix.as_bytes())?;
        let byte = self.pending.first().copied().unwrap_or_default();
        let valid = self.used();
        let reader = if valid == 0 {
            self.backend.finalize(None)?
        } else {
            let bytes = [byte];
            let tail = Fips202BitString::new(&bytes, valid)
                .map_err(|_| TupleHashError::InvalidBitString)?;
            self.backend.finalize(Some(tail))?
        };
        let _ = clear_owned_region(&mut self.pending);
        let _ = clear_owned_region(&mut self.used);
        Ok(reader)
    }

    pub(crate) fn abandon_item(&mut self) {
        self.failed = [1];
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

#[cfg(test)]
pub(crate) mod assurance_contract {
    use brynja_hash_sha3::Fips202BitString;

    use super::TupleCore;

    #[test]
    fn registered_algorithm_tuplehash_owner_contract_is_compiler_checked() {
        let customization = Fips202BitString::new(&[], 0);
        assert!(customization.is_ok());
        let Ok(customization) = customization else {
            return;
        };
        let owner = TupleCore::new(128, customization);
        assert!(owner.is_ok());
        let Ok(mut owner) = owner else {
            return;
        };
        owner.pending.fill(0xa5);
        owner.used.fill(0x05);
        owner.items.fill(0x5a);
        owner.failed.fill(0x01);
        owner.wipe();
        assert!(owner.pending.iter().all(|byte| *byte == 0));
        assert!(owner.used.iter().all(|byte| *byte == 0));
        assert!(owner.items.iter().all(|byte| *byte == 0));
        assert!(owner.failed.iter().all(|byte| *byte == 0));
    }
}
