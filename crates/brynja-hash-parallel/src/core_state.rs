use crate::secret_encoding::SecretEncodedInteger as Encoded;
use brynja_core::clear_owned_region;
use brynja_hash_sha3::{Fips202BitString, Fips202Output};

use crate::{
    ParallelHashError,
    backend::{Backend, BackendReader, LEAF_128_BYTES, LEAF_256_BYTES, Strength, leaf128, leaf256},
};

pub(crate) struct ParallelCore<'workspace> {
    outer: Backend,
    workspace: &'workspace mut [u8],
    used: [u8; 16],
    leaves: [u8; 16],
    failed: [u8; 1],
    strength: Strength,
}

impl<'workspace> ParallelCore<'workspace> {
    pub(crate) fn new(
        workspace: &'workspace mut [u8],
        strength: Strength,
        customization: Fips202BitString<'_>,
    ) -> Result<Self, ParallelHashError> {
        if workspace.is_empty() {
            return Err(ParallelHashError::InvalidBlockSize);
        }
        let block_size =
            u128::try_from(workspace.len()).map_err(|_| ParallelHashError::InvalidBlockSize)?;
        let mut outer = Backend::outer(strength, customization)?;
        let mut prefix = Encoded::empty();
        prefix.left(block_size)?;
        outer.update(prefix.bytes()?)?;
        let _ = clear_owned_region(workspace);
        Ok(Self {
            outer,
            workspace,
            used: [0; 16],
            leaves: [0; 16],
            failed: [0],
            strength,
        })
    }

    pub(crate) fn block_size(&self) -> usize {
        self.workspace.len()
    }

    pub(crate) fn leaf_count(&self) -> u128 {
        read_u128(&self.leaves)
    }

    pub(crate) fn update(&mut self, input: &[u8]) -> Result<(), ParallelHashError> {
        self.ensure_live()?;
        if let Err(error) = self.preflight(input.len()) {
            self.fail();
            return Err(error);
        }
        let result = self.update_inner(input);
        if result.is_err() {
            self.fail();
        }
        result
    }

    fn update_inner(&mut self, mut input: &[u8]) -> Result<(), ParallelHashError> {
        while !input.is_empty() {
            let used = self.used()?;
            let capacity = self
                .workspace
                .len()
                .checked_sub(used)
                .ok_or(ParallelHashError::StateConsumed)?;
            let take = core::cmp::min(capacity, input.len());
            let end = used
                .checked_add(take)
                .ok_or(ParallelHashError::MessageTooLong)?;
            let target = self
                .workspace
                .get_mut(used..end)
                .ok_or(ParallelHashError::StateConsumed)?;
            let source = input.get(..take).ok_or(ParallelHashError::MessageTooLong)?;
            brynja_core::copy_secret_region(target, source)
                .map_err(|_| ParallelHashError::SecretMemory)?;
            self.set_used(end)?;
            input = input.get(take..).ok_or(ParallelHashError::MessageTooLong)?;
            if end == self.workspace.len() {
                self.absorb_pending(8)?;
            }
        }
        Ok(())
    }

    pub(crate) fn finalize_input(
        &mut self,
        tail: Option<Fips202BitString<'_>>,
    ) -> Result<(), ParallelHashError> {
        self.ensure_live()?;
        let result = self.finalize_input_inner(tail);
        if result.is_err() {
            self.fail();
        }
        result
    }

    fn finalize_input_inner(
        &mut self,
        tail: Option<Fips202BitString<'_>>,
    ) -> Result<(), ParallelHashError> {
        if let Some(tail) = tail {
            let bytes = tail.as_bytes();
            let complete = if tail.is_byte_aligned() {
                bytes
            } else {
                bytes
                    .get(
                        ..bytes
                            .len()
                            .checked_sub(1)
                            .ok_or(ParallelHashError::InvalidBitString)?,
                    )
                    .ok_or(ParallelHashError::InvalidBitString)?
            };
            self.update(complete)?;
            if !tail.is_byte_aligned() {
                let byte = bytes.last().ok_or(ParallelHashError::InvalidBitString)?;
                let used = self.used()?;
                let Some(target) = self.workspace.get_mut(used) else {
                    return Err(ParallelHashError::MessageTooLong);
                };
                brynja_core::copy_secret_region(
                    core::slice::from_mut(target),
                    core::slice::from_ref(byte),
                )
                .map_err(|_| ParallelHashError::SecretMemory)?;
                self.set_used(
                    used.checked_add(1)
                        .ok_or(ParallelHashError::MessageTooLong)?,
                )?;
                self.absorb_pending(tail.valid_bits_in_last_byte())?;
                return Ok(());
            }
        }
        if self.used()? != 0 {
            self.absorb_pending(8)?;
        }
        Ok(())
    }

    pub(crate) fn finish(
        &mut self,
        expected_leaves: Option<u128>,
        output_bits: u128,
    ) -> Result<BackendReader<'_>, ParallelHashError> {
        self.ensure_live()?;
        if self.used()? != 0 {
            self.fail();
            return Err(ParallelHashError::StateConsumed);
        }
        if expected_leaves.is_some_and(|expected| expected != self.leaf_count()) {
            self.fail();
            return Err(ParallelHashError::LeafOrder);
        }
        self.failed = [1];
        let mut suffix = Encoded::empty();
        suffix.right(self.leaf_count())?;
        self.outer.update(suffix.bytes()?)?;
        suffix.right(output_bits)?;
        self.outer.update(suffix.bytes()?)?;
        let reader = self.outer.finalize_in_place()?;
        let _ = clear_owned_region(&mut self.used);
        let _ = clear_owned_region(&mut self.leaves);
        let _ = clear_owned_region(&mut self.failed);
        Ok(reader)
    }

    pub(crate) fn cancel(&mut self) {
        self.wipe();
    }

    fn preflight(&self, additional: usize) -> Result<(), ParallelHashError> {
        let total = self
            .used()?
            .checked_add(additional)
            .ok_or(ParallelHashError::MessageTooLong)?;
        let full = total
            .checked_div(self.workspace.len())
            .ok_or(ParallelHashError::InvalidBlockSize)?;
        let full = u128::try_from(full).map_err(|_| ParallelHashError::MessageTooLong)?;
        self.leaf_count()
            .checked_add(full)
            .ok_or(ParallelHashError::MessageTooLong)
            .map(|_| ())
    }

    fn absorb_pending(&mut self, valid: u8) -> Result<(), ParallelHashError> {
        let used = self.used()?;
        let input = self
            .workspace
            .get(..used)
            .ok_or(ParallelHashError::StateConsumed)?;
        let bit_string =
            Fips202BitString::new(input, valid).map_err(|_| ParallelHashError::InvalidBitString)?;
        match self.strength {
            Strength::Bits128 => {
                let mut digest = [0_u8; LEAF_128_BYTES];
                let owned = leaf128(bit_string, &mut digest)?;
                self.outer.update(owned.expose())?;
                drop(owned);
            }
            Strength::Bits256 => {
                let mut digest = [0_u8; LEAF_256_BYTES];
                let owned = leaf256(bit_string, &mut digest)?;
                self.outer.update(owned.expose())?;
                drop(owned);
            }
        }
        self.increment_leaves()?;
        let _ = clear_owned_region(self.workspace);
        let _ = clear_owned_region(&mut self.used);
        Ok(())
    }

    fn increment_leaves(&mut self) -> Result<(), ParallelHashError> {
        let next = self
            .leaf_count()
            .checked_add(1)
            .ok_or(ParallelHashError::MessageTooLong)?;
        write_u128(&mut self.leaves, next)
    }

    fn ensure_live(&self) -> Result<(), ParallelHashError> {
        if self.failed.first().copied().unwrap_or(1) == 0 {
            Ok(())
        } else {
            Err(ParallelHashError::StateConsumed)
        }
    }

    fn used(&self) -> Result<usize, ParallelHashError> {
        usize::try_from(read_u128(&self.used)).map_err(|_| ParallelHashError::StateConsumed)
    }

    fn set_used(&mut self, value: usize) -> Result<(), ParallelHashError> {
        let value = u128::try_from(value).map_err(|_| ParallelHashError::MessageTooLong)?;
        write_u128(&mut self.used, value)
    }

    fn fail(&mut self) {
        self.failed = [1];
        self.outer.wipe();
        let _ = clear_owned_region(self.workspace);
        let _ = clear_owned_region(&mut self.used);
        let _ = clear_owned_region(&mut self.leaves);
    }

    #[inline(never)]
    fn wipe(&mut self) {
        self.outer.wipe();
        let _ = clear_owned_region(self.workspace);
        let _ = clear_owned_region(&mut self.used);
        let _ = clear_owned_region(&mut self.leaves);
        let _ = clear_owned_region(&mut self.failed);
    }
}

impl Drop for ParallelCore<'_> {
    fn drop(&mut self) {
        self.wipe();
    }
}

pub(crate) fn byte_string(input: &[u8]) -> Result<Fips202BitString<'_>, ParallelHashError> {
    let valid = if input.is_empty() { 0 } else { 8 };
    Fips202BitString::new(input, valid).map_err(|_| ParallelHashError::InvalidBitString)
}

pub(crate) fn output_bits(length: usize) -> Result<u128, ParallelHashError> {
    u128::try_from(length)
        .ok()
        .and_then(|value| value.checked_mul(8))
        .ok_or(ParallelHashError::OutputTooLong)
}

fn read_u128(bytes: &[u8; 16]) -> u128 {
    let mut value = 0_u128;
    for (index, byte) in bytes.iter().enumerate() {
        value |= u128::from(*byte) << index.saturating_mul(8);
    }
    value
}

fn write_u128(bytes: &mut [u8; 16], value: u128) -> Result<(), ParallelHashError> {
    for (index, byte) in bytes.iter_mut().enumerate() {
        let shift = index.saturating_mul(8);
        *byte = u8::try_from((value >> shift) & u128::from(u8::MAX))
            .map_err(|_| ParallelHashError::MessageTooLong)?;
    }
    Ok(())
}

pub(crate) fn finish_public(
    reader: &mut BackendReader<'_>,
    output: &mut [u8],
) -> Result<(), ParallelHashError> {
    reader
        .squeeze_public(output)
        .map_err(ParallelHashError::from)
}

pub(crate) fn finish_public_bits(
    reader: BackendReader<'_>,
    output: Fips202Output<'_>,
) -> Result<(), ParallelHashError> {
    reader
        .squeeze_final_public(output)
        .map_err(ParallelHashError::from)
}

#[cfg(test)]
pub(crate) mod assurance_contract {
    use super::{ParallelCore, Strength};
    use crate::{Fips202BitString, ParallelHashError as Error};

    #[test]
    fn borrowed_buffering_preserves_bytes_and_clears() -> Result<(), Error> {
        let mut input = [0_u8; 256];
        for (index, byte) in input.iter_mut().enumerate() {
            *byte = index.to_le_bytes()[0];
        }
        for strength in [Strength::Bits128, Strength::Bits256] {
            let mut storage = [0xa5; 257];
            let mut owner = ParallelCore::new(&mut storage, strength, super::byte_string(b"")?)?;
            for (index, byte) in input.iter().enumerate() {
                owner.update(core::slice::from_ref(byte))?;
                owner.update(&[])?;
                assert_eq!(owner.used()?, index + 1);
                assert_eq!(owner.workspace.get(..=index), input.get(..=index));
                assert!(
                    owner
                        .workspace
                        .get(index + 1..)
                        .ok_or(Error::StateConsumed)?
                        .iter()
                        .all(|b| *b == 0)
                );
            }
            owner.cancel();
            assert!(owner.workspace.iter().all(|b| *b == 0));
            drop(owner);
            assert_eq!(storage, [0; 257]);
        }
        Ok(())
    }

    // This reference groups input directly into leaf slices; it never copies
    // through ParallelCore's buffering/final-tail paths under test.
    fn direct_leaf_reference(
        strength: Strength,
        input: Fips202BitString<'_>,
        block: usize,
        output_bits: u128,
    ) -> Result<[u8; 32], Error> {
        let mut root = super::Backend::outer(strength, super::byte_string(b"")?)?;
        let mut encoding = super::Encoded::empty();
        encoding.left(u128::try_from(block).map_err(|_| Error::InvalidBlockSize)?)?;
        root.update(encoding.bytes()?)?;
        let mut leaves = 0_u128;
        let mut position = 0_usize;
        for chunk in input.as_bytes().chunks(block) {
            position = position
                .checked_add(chunk.len())
                .ok_or(Error::MessageTooLong)?;
            let valid = if position == input.as_bytes().len() {
                input.valid_bits_in_last_byte()
            } else {
                8
            };
            let bits = Fips202BitString::new(chunk, valid).map_err(|_| Error::InvalidBitString)?;
            match strength {
                Strength::Bits128 => {
                    let mut output = [0; 32];
                    let secret = super::leaf128(bits, &mut output)?;
                    root.update(secret.expose())?;
                }
                Strength::Bits256 => {
                    let mut output = [0; 64];
                    let secret = super::leaf256(bits, &mut output)?;
                    root.update(secret.expose())?;
                }
            }
            leaves = leaves.checked_add(1).ok_or(Error::MessageTooLong)?;
        }
        encoding.right(leaves)?;
        root.update(encoding.bytes()?)?;
        encoding.right(output_bits)?;
        root.update(encoding.bytes()?)?;
        let mut output = [0; 32];
        root.finalize_in_place()?.squeeze_public(&mut output)?;
        Ok(output)
    }

    #[test]
    fn borrowed_buffering_and_tails_match_direct_leaves() -> Result<(), Error> {
        for strength in [Strength::Bits128, Strength::Bits256] {
            for block in [1_usize, 2, 7, 64, 136, 168, 169] {
                for length in [0, 1, block - 1, block, block + 1, block * 2 + 1] {
                    for valid in 1..=8 {
                        let mut input = [0_u8; 339];
                        for (index, byte) in input.iter_mut().enumerate() {
                            *byte = index.to_le_bytes()[0].wrapping_mul(29).wrapping_add(0xa5);
                        }
                        let input = input.get_mut(..length).ok_or(Error::StateConsumed)?;
                        if let Some(last) = input.last_mut() {
                            *last &= u8::MAX >> (8 - valid);
                        }
                        let bits =
                            Fips202BitString::new(input, if length == 0 { 0 } else { valid })
                                .map_err(|_| Error::InvalidBitString)?;
                        for output_bits in [0, 256] {
                            let expected =
                                direct_leaf_reference(strength, bits, block, output_bits)?;
                            let mut storage = [0xa5; 169];
                            let storage = storage.get_mut(..block).ok_or(Error::StateConsumed)?;
                            let mut owner =
                                ParallelCore::new(storage, strength, super::byte_string(b"")?)?;
                            if let Some((last, prefix)) = input.split_last() {
                                for chunk in prefix.chunks(13) {
                                    owner.update(chunk)?;
                                }
                                owner.finalize_input(Some(
                                    Fips202BitString::new(core::slice::from_ref(last), valid)
                                        .map_err(|_| Error::InvalidBitString)?,
                                ))?;
                            } else {
                                owner.finalize_input(Some(bits))?;
                            }
                            assert!(owner.workspace.iter().all(|byte| *byte == 0));
                            assert_eq!(owner.used()?, 0);
                            let mut output = [0xa5; 32];
                            let mut reader = owner.finish(None, output_bits)?;
                            let secret = reader.squeeze_secret(&mut output)?;
                            assert_eq!(secret.expose(), expected);
                            drop(secret);
                            assert_eq!(output, [0; 32]);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn borrowed_buffering_rejections_clear_and_close() -> Result<(), Error> {
        for finalizing in [false, true] {
            let mut storage = [0xa5; 8];
            let mut owner =
                ParallelCore::new(&mut storage, Strength::Bits128, super::byte_string(b"")?)?;
            owner.update(b"secret")?;
            if finalizing {
                owner.leaves = u128::MAX.to_le_bytes();
                let tail = Fips202BitString::new(&[1], 1).map_err(|_| Error::InvalidBitString)?;
                assert_eq!(owner.finalize_input(Some(tail)), Err(Error::MessageTooLong));
            } else {
                owner.set_used(9)?;
                assert_eq!(owner.update(b"x"), Err(Error::StateConsumed));
            }
            assert_eq!(owner.update(b"x"), Err(Error::StateConsumed));
            assert!(owner.workspace.iter().all(|byte| *byte == 0));
            assert_eq!(owner.used, [0; 16]);
            assert_eq!(owner.leaves, [0; 16]);
        }
        Ok(())
    }

    #[test]
    fn registered_algorithm_parallelhash_owner_contract_is_compiler_checked() {
        let customization = Fips202BitString::new(&[], 0);
        assert!(customization.is_ok());
        let Ok(customization) = customization else {
            return;
        };
        let mut workspace = [0xa5_u8; 8];
        let owner = ParallelCore::new(&mut workspace, Strength::Bits128, customization);
        assert!(owner.is_ok());
        let Ok(mut owner) = owner else {
            return;
        };
        owner.used.fill(0x05);
        owner.leaves.fill(0x5a);
        owner.failed.fill(0x01);
        owner.wipe();
        assert!(owner.workspace.iter().all(|byte| *byte == 0));
        assert!(owner.used.iter().all(|byte| *byte == 0));
        assert!(owner.leaves.iter().all(|byte| *byte == 0));
        assert!(owner.failed.iter().all(|byte| *byte == 0));
    }
}
