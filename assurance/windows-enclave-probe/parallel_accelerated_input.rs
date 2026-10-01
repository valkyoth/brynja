//! Sequential, bounded-memory leaves; B does not determine an allocation size.
use super::parallel_accelerated_state::State;
use super::parallel_stream_encoding::SecretEncodedInteger;
use super::{Bits, Error, empty};
use brynja_core::clear_owned_region;

pub(super) struct Input<'cpu> {
    authority: &'cpu brynja_crypto_cpu::static_execution::Authority,
    leaf: State<'cpu>,
    used: [u8; 16],
    leaves: [u8; 16],
    bits: [u8; 16],
    block: u64,
    identity: u64,
}
impl<'cpu> Input<'cpu> {
    pub(super) const fn new(
        authority: &'cpu brynja_crypto_cpu::static_execution::Authority,
    ) -> Self {
        Self {
            authority,
            leaf: State::Empty,
            used: [0; 16],
            leaves: [0; 16],
            bits: [0; 16],
            block: 0,
            identity: 0,
        }
    }
    pub(super) fn clear(&mut self) {
        self.leaf = State::Empty;
        let _ = clear_owned_region(&mut self.used);
        let _ = clear_owned_region(&mut self.leaves);
        let _ = clear_owned_region(&mut self.bits);
        self.block = 0;
        self.identity = 0;
    }
    pub(super) fn begin(&mut self, identity: u64, block: u64) -> Result<(), Error> {
        self.clear();
        if block == 0 || !(1..=4).contains(&identity) {
            return Err(Error::Identity);
        }
        self.block = block;
        self.identity = identity;
        Ok(())
    }
    fn add_bits(&mut self, bits: usize) -> Result<(), Error> {
        self.bits = u128::from_le_bytes(self.bits)
            .checked_add(u128::try_from(bits).map_err(|_| Error::Length)?)
            .ok_or(Error::Length)?
            .to_le_bytes();
        Ok(())
    }
    fn absorb(&mut self, root: &mut State<'cpu>, mut input: &[u8]) -> Result<(), Error> {
        while !input.is_empty() {
            let used = u128::from_le_bytes(self.used);
            let block = u128::from(self.block);
            if used >= block {
                return Err(Error::State);
            }
            if used == 0 {
                self.leaf = State::leaf(self.authority, self.identity)?;
            }
            let available = block.checked_sub(used).ok_or(Error::State)?;
            let take = usize::try_from(
                available.min(u128::try_from(input.len()).map_err(|_| Error::Length)?),
            )
            .map_err(|_| Error::Length)?;
            self.leaf.update(input.get(..take).ok_or(Error::Length)?)?;
            self.used = used
                .checked_add(u128::try_from(take).map_err(|_| Error::Length)?)
                .ok_or(Error::Length)?
                .to_le_bytes();
            input = input.get(take..).ok_or(Error::Length)?;
            if u128::from_le_bytes(self.used) == block {
                self.flush(root, empty()?)?;
            }
        }
        Ok(())
    }
    fn flush(&mut self, root: &mut State<'cpu>, tail: Bits<'_>) -> Result<(), Error> {
        let used = u128::from_le_bytes(self.used);
        if used > u128::from(self.block)
            || (used == 0 && tail.bit_len() == 0)
            || (tail.bit_len() != 0 && used >= u128::from(self.block))
        {
            return Err(Error::State);
        }
        let count = u128::from_le_bytes(self.leaves)
            .checked_add(1)
            .ok_or(Error::Length)?;
        if used == 0 {
            self.leaf = State::leaf(self.authority, self.identity)?;
        }
        self.leaf.finish(tail)?;
        let mut cv = Cv([0; 64]);
        let width = if matches!(self.identity, 1 | 3) {
            32
        } else {
            64
        };
        let output = cv.0.get_mut(..width).ok_or(Error::Length)?;
        self.leaf.squeeze(output, 8, true)?;
        root.update(output)?;
        self.leaf = State::Empty;
        let _ = clear_owned_region(&mut self.used);
        self.leaves = count.to_le_bytes();
        Ok(())
    }
    pub(super) fn update(&mut self, root: &mut State<'cpu>, input: &[u8]) -> Result<(), Error> {
        self.add_bits(input.len().checked_mul(8).ok_or(Error::Length)?)?;
        self.absorb(root, input)
    }
    pub(super) fn finish(&mut self, root: &mut State<'cpu>, tail: Bits<'_>) -> Result<(), Error> {
        self.add_bits(tail.bit_len())?;
        let complete = tail.bit_len() / 8;
        self.absorb(root, tail.as_bytes().get(..complete).ok_or(Error::Bits)?)?;
        if !tail.is_byte_aligned() {
            let bits = Bits::new(
                tail.as_bytes().get(complete..).ok_or(Error::Bits)?,
                tail.valid_bits_in_last_byte(),
            )
            .map_err(|_| Error::Bits)?;
            self.flush(root, bits)?;
        } else if self.used != [0; 16] {
            self.flush(root, empty()?)?;
        }
        self.check_complete()?;
        let mut suffix = SecretEncodedInteger::empty();
        suffix.right(u128::from_le_bytes(self.leaves))?;
        root.update(suffix.bytes()?)?;
        self.clear();
        Ok(())
    }
    fn check_complete(&self) -> Result<(), Error> {
        let total = u128::from_le_bytes(self.bits);
        let block_bits = u128::from(self.block).checked_mul(8).ok_or(Error::Length)?;
        let expected = total
            .checked_div(block_bits)
            .ok_or(Error::Length)?
            .checked_add(u128::from(
                total.checked_rem(block_bits).ok_or(Error::Length)? != 0,
            ))
            .ok_or(Error::Length)?;
        if self.used != [0; 16] || u128::from_le_bytes(self.leaves) != expected {
            return Err(Error::State);
        }
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn cleared(&self) -> bool {
        matches!(self.leaf, State::Empty)
            && self.used == [0; 16]
            && self.leaves == [0; 16]
            && self.bits == [0; 16]
            && self.block == 0
            && self.identity == 0
    }
    #[cfg(test)]
    pub(super) fn corrupt(&mut self, used: u128, leaves: u128, bits: u128) {
        self.used = used.to_le_bytes();
        self.leaves = leaves.to_le_bytes();
        self.bits = bits.to_le_bytes();
    }
}
impl Drop for Input<'_> {
    fn drop(&mut self) {
        self.clear();
    }
}
struct Cv([u8; 64]);
impl Drop for Cv {
    fn drop(&mut self) {
        let _ = clear_owned_region(&mut self.0);
    }
}
