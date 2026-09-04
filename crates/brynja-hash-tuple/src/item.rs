use brynja_hash_sha3::Fips202BitString;

use crate::{TupleHashError, core_state::TupleCore};

/// Affine writer for exactly one declared tuple item.
///
/// Dropping this value before [`finish`](Self::finish) permanently closes its
/// parent. This prevents a partially encoded item from being mistaken for a
/// complete tuple member.
#[must_use = "an item must consume its declared length and be finished"]
pub struct TupleItemWriter<'state> {
    pub(crate) core: &'state mut TupleCore,
    complete: bool,
}

impl<'state> TupleItemWriter<'state> {
    pub(crate) const fn new(core: &'state mut TupleCore) -> Self {
        Self {
            core,
            complete: false,
        }
    }

    /// Returns the exact number of item bits still required.
    #[must_use]
    pub fn remaining_bits(&self) -> u128 {
        self.core.item_remaining()
    }

    /// Appends complete bytes or rejects without mutation.
    pub fn update(&mut self, input: &[u8]) -> Result<(), TupleHashError> {
        let bits = u128::try_from(input.len())
            .ok()
            .and_then(|value| value.checked_mul(8))
            .ok_or(TupleHashError::MessageTooLong)?;
        self.core.check_item_fragment(bits)?;
        self.core.push_bytes(input)?;
        self.core.consume_item(bits)?;
        Ok(())
    }

    /// Appends one canonical arbitrary-bit fragment or rejects without mutation.
    pub fn update_bits(&mut self, input: Fips202BitString<'_>) -> Result<(), TupleHashError> {
        let bits = u128::try_from(input.bit_len()).map_err(|_| TupleHashError::MessageTooLong)?;
        self.core.check_item_fragment(bits)?;
        self.core.push_bit_string(input)?;
        self.core.consume_item(bits)?;
        Ok(())
    }

    /// Completes this item only when its declared length was consumed exactly.
    pub fn finish(mut self) -> Result<(), TupleHashError> {
        self.core.complete_item()?;
        self.complete = true;
        Ok(())
    }
}

impl Drop for TupleItemWriter<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.core.abandon_item();
        }
    }
}
