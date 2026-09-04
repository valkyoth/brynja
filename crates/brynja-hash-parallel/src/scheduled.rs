use brynja_core::clear_owned_region;
use brynja_hash_sha3::{
    Fips202BitString, Fips202Output, HardenedSha3SecretOutput, left_encode_u128, right_encode_u128,
};

use crate::{
    ParallelHashError, ParallelHashSecretOutput,
    backend::{Backend, LEAF_128_BYTES, LEAF_256_BYTES, Strength, leaf128, leaf256},
    core_state::{byte_string, output_bits},
};

macro_rules! plan {
    ($plan:ident, $job:ident, $result:ident, $leaf:ident, $size:ident) => {
        /// Immutable division of one input into exact SP 800-185 leaves.
        pub struct $plan<'input> {
            input: Fips202BitString<'input>,
            block_size: usize,
            leaves: u128,
            identity: PlanIdentity,
        }

        impl<'input> $plan<'input> {
            /// Plans byte-oriented input with positive block size `B`.
            pub fn new(input: &'input [u8], block_size: usize) -> Result<Self, ParallelHashError> {
                Self::new_bits(byte_string(input)?, block_size)
            }

            /// Plans canonical arbitrary-bit input with positive block size `B`.
            pub fn new_bits(
                input: Fips202BitString<'input>,
                block_size: usize,
            ) -> Result<Self, ParallelHashError> {
                let leaves = leaf_count(input.bit_len(), block_size)?;
                Ok(Self {
                    input,
                    block_size,
                    leaves,
                    identity: PlanIdentity(0),
                })
            }

            /// Returns the exact number of leaf jobs.
            #[must_use]
            pub const fn leaf_count(&self) -> u128 {
                self.leaves
            }

            /// Returns one exact indexed leaf job.
            pub fn job<'plan>(
                &'plan self,
                index: u128,
            ) -> Result<$job<'plan, 'input>, ParallelHashError> {
                leaf_slice(self.input, self.block_size, self.leaves, index).map(|input| $job {
                    index,
                    leaf_count: self.leaves,
                    block_size: self.block_size,
                    input,
                    identity: &self.identity,
                })
            }
        }

        /// One exact, independently executable leaf job.
        pub struct $job<'plan, 'input> {
            index: u128,
            leaf_count: u128,
            block_size: usize,
            input: Fips202BitString<'input>,
            identity: &'plan PlanIdentity,
        }

        impl<'plan, 'input> $job<'plan, 'input> {
            /// Returns this leaf's zero-based index.
            #[must_use]
            pub const fn index(&self) -> u128 {
                self.index
            }

            /// Computes this leaf into caller-owned result storage.
            pub fn execute<'output>(
                self,
                output: &'output mut [u8; $size],
            ) -> Result<$result<'plan, 'output>, ParallelHashError> {
                $leaf(self.input, output)
                    .map(|inner| $result {
                        index: self.index,
                        leaf_count: self.leaf_count,
                        block_size: self.block_size,
                        identity: self.identity,
                        inner,
                    })
                    .map_err(ParallelHashError::from)
            }
        }

        /// Typed caller-owned result for one scheduled leaf.
        #[must_use = "a leaf result must be merged or dropped for clearing"]
        pub struct $result<'plan, 'output> {
            index: u128,
            leaf_count: u128,
            block_size: usize,
            identity: &'plan PlanIdentity,
            inner: HardenedSha3SecretOutput<'output>,
        }

        impl $result<'_, '_> {
            /// Borrows the complete leaf value while typed ownership remains active.
            #[must_use]
            pub fn expose(&self) -> &[u8] {
                self.inner.expose()
            }

            pub(crate) fn parts(&self) -> (u128, u128, usize, &PlanIdentity, &[u8]) {
                (
                    self.index,
                    self.leaf_count,
                    self.block_size,
                    self.identity,
                    self.inner.expose(),
                )
            }
        }
    };
}

pub(crate) struct PlanIdentity(u8);

plan!(
    ParallelHash128Plan,
    ParallelHash128LeafJob,
    ParallelHash128LeafResult,
    leaf128,
    LEAF_128_BYTES
);
plan!(
    ParallelHash256Plan,
    ParallelHash256LeafJob,
    ParallelHash256LeafResult,
    leaf256,
    LEAF_256_BYTES
);

macro_rules! collector {
    ($collector:ident, $plan:ident, $result:ident, $strength:expr) => {
        /// Ordered final-node collector for caller-scheduled leaves.
        pub struct $collector<'plan> {
            outer: Backend,
            block_size: usize,
            expected: u128,
            identity: &'plan PlanIdentity,
            merged: [u8; 16],
            failed: bool,
        }

        impl<'plan> $collector<'plan> {
            /// Creates a collector bound to one exact plan and byte customization.
            pub fn new(
                plan: &'plan $plan<'_>,
                customization: &[u8],
            ) -> Result<Self, ParallelHashError> {
                Self::new_bits(plan, byte_string(customization)?)
            }

            /// Creates a plan-bound collector with arbitrary-bit customization.
            pub fn new_bits(
                plan: &'plan $plan<'_>,
                customization: Fips202BitString<'_>,
            ) -> Result<Self, ParallelHashError> {
                let mut outer = Backend::outer($strength, customization)?;
                let block = u128::try_from(plan.block_size)
                    .map_err(|_| ParallelHashError::InvalidBlockSize)?;
                outer.update(left_encode_u128(block).as_bytes())?;
                Ok(Self {
                    outer,
                    block_size: plan.block_size,
                    expected: plan.leaves,
                    identity: &plan.identity,
                    merged: [0; 16],
                    failed: false,
                })
            }

            /// Merges exactly the next leaf. Any mismatch permanently fails.
            pub fn merge(&mut self, result: &$result<'plan, '_>) -> Result<(), ParallelHashError> {
                self.ensure_live()?;
                let merged = self.merge_inner(result);
                if merged.is_err() {
                    self.fail();
                }
                merged
            }

            fn merge_inner(
                &mut self,
                result: &$result<'plan, '_>,
            ) -> Result<(), ParallelHashError> {
                let (index, count, block_size, identity, digest) = result.parts();
                if identity.0 != self.identity.0
                    || !core::ptr::eq(identity, self.identity)
                    || count != self.expected
                    || block_size != self.block_size
                {
                    return Err(ParallelHashError::LeafIdentity);
                }
                if index != self.merged() || index >= self.expected {
                    return Err(ParallelHashError::LeafOrder);
                }
                self.outer.update(digest)?;
                self.set_merged(
                    index
                        .checked_add(1)
                        .ok_or(ParallelHashError::MessageTooLong)?,
                )
            }

            /// Finalizes fixed output after every planned leaf was merged.
            pub fn finalize(&mut self, output: &mut [u8]) -> Result<(), ParallelHashError> {
                let bits = output_bits(output.len())?;
                let mut reader = self.finish(bits)?;
                reader
                    .squeeze_public(output)
                    .map_err(ParallelHashError::from)
            }

            /// Finalizes fixed arbitrary-bit output after every leaf.
            pub fn finalize_bits(
                &mut self,
                output: Fips202Output<'_>,
            ) -> Result<(), ParallelHashError> {
                let bits = u128::try_from(output.bit_len())
                    .map_err(|_| ParallelHashError::OutputTooLong)?;
                self.finish(bits)?
                    .squeeze_final_public(output)
                    .map_err(ParallelHashError::from)
            }

            /// Finalizes fixed output with typed secret ownership.
            pub fn finalize_secret<'a>(
                &mut self,
                output: &'a mut [u8],
            ) -> Result<ParallelHashSecretOutput<'a>, ParallelHashError> {
                let bits = output_bits(output.len())?;
                self.finish(bits)?
                    .squeeze_secret(output)
                    .map(ParallelHashSecretOutput::new)
                    .map_err(ParallelHashError::from)
            }

            /// Enters XOF output after every planned leaf was merged.
            fn finish_xof_backend(
                &mut self,
            ) -> Result<crate::backend::BackendReader<'_>, ParallelHashError> {
                self.finish(0)
            }

            /// Clears this collector without output.
            pub fn cancel(&mut self) {
                self.fail();
            }

            fn finish(
                &mut self,
                output_bits: u128,
            ) -> Result<crate::backend::BackendReader<'_>, ParallelHashError> {
                self.ensure_live()?;
                if self.merged() != self.expected {
                    self.fail();
                    return Err(ParallelHashError::LeafOrder);
                }
                self.failed = true;
                self.outer
                    .update(right_encode_u128(self.expected).as_bytes())?;
                self.outer
                    .update(right_encode_u128(output_bits).as_bytes())?;
                let reader = self.outer.finalize_in_place()?;
                let _ = clear_owned_region(&mut self.merged);
                Ok(reader)
            }

            fn merged(&self) -> u128 {
                read_u128(&self.merged)
            }

            fn set_merged(&mut self, value: u128) -> Result<(), ParallelHashError> {
                write_u128(&mut self.merged, value)
            }

            fn ensure_live(&self) -> Result<(), ParallelHashError> {
                if self.failed {
                    Err(ParallelHashError::StateConsumed)
                } else {
                    Ok(())
                }
            }

            fn fail(&mut self) {
                self.failed = true;
                self.outer.wipe();
                let _ = clear_owned_region(&mut self.merged);
            }
        }

        impl Drop for $collector<'_> {
            fn drop(&mut self) {
                self.fail();
            }
        }
    };
}

collector!(
    ParallelHash128Collector,
    ParallelHash128Plan,
    ParallelHash128LeafResult,
    Strength::Bits128
);

/// Incremental output from a scheduled ParallelHashXOF128 collection.
pub struct ParallelHash128ScheduledXofReader<'state> {
    inner: crate::backend::BackendReader<'state>,
}

/// Incremental output from a scheduled ParallelHashXOF256 collection.
pub struct ParallelHash256ScheduledXofReader<'state> {
    inner: crate::backend::BackendReader<'state>,
}

macro_rules! scheduled_reader {
    ($collector:ident, $reader:ident) => {
        impl $collector<'_> {
            /// Enters XOF mode after every planned leaf was merged.
            pub fn finalize_xof(&mut self) -> Result<$reader<'_>, ParallelHashError> {
                self.finish_xof_backend().map(|inner| $reader { inner })
            }
        }

        impl $reader<'_> {
            /// Writes one explicitly declassified public fragment.
            pub fn squeeze_public(
                &mut self,
                output: &mut [u8],
                _authority: crate::ParallelHashPublicDeclassification,
            ) -> Result<(), ParallelHashError> {
                self.inner
                    .squeeze_public(output)
                    .map_err(ParallelHashError::from)
            }

            /// Writes one fragment with typed secret ownership.
            pub fn squeeze_secret<'a>(
                &mut self,
                output: &'a mut [u8],
            ) -> Result<ParallelHashSecretOutput<'a>, ParallelHashError> {
                self.inner
                    .squeeze_secret(output)
                    .map(ParallelHashSecretOutput::new)
                    .map_err(ParallelHashError::from)
            }

            /// Writes one final arbitrary-bit public fragment.
            pub fn squeeze_final_bits_public(
                self,
                output: Fips202Output<'_>,
                _authority: crate::ParallelHashPublicDeclassification,
            ) -> Result<(), ParallelHashError> {
                self.inner
                    .squeeze_final_public(output)
                    .map_err(ParallelHashError::from)
            }

            /// Writes one final arbitrary-bit secret fragment.
            pub fn squeeze_final_bits_secret<'a>(
                self,
                output: Fips202Output<'a>,
            ) -> Result<ParallelHashSecretOutput<'a>, ParallelHashError> {
                self.inner
                    .squeeze_final_secret(output)
                    .map(ParallelHashSecretOutput::new)
                    .map_err(ParallelHashError::from)
            }
        }
    };
}

scheduled_reader!(ParallelHash128Collector, ParallelHash128ScheduledXofReader);
scheduled_reader!(ParallelHash256Collector, ParallelHash256ScheduledXofReader);
collector!(
    ParallelHash256Collector,
    ParallelHash256Plan,
    ParallelHash256LeafResult,
    Strength::Bits256
);

pub(crate) fn leaf_count(bit_length: usize, block_size: usize) -> Result<u128, ParallelHashError> {
    let block_bits = block_size
        .checked_mul(8)
        .ok_or(ParallelHashError::InvalidBlockSize)?;
    if block_bits == 0 {
        return Err(ParallelHashError::InvalidBlockSize);
    }
    let complete = bit_length
        .checked_div(block_bits)
        .ok_or(ParallelHashError::InvalidBlockSize)?;
    let remainder = bit_length
        .checked_rem(block_bits)
        .ok_or(ParallelHashError::InvalidBlockSize)?;
    let leaves = complete
        .checked_add(usize::from(remainder != 0))
        .ok_or(ParallelHashError::MessageTooLong)?;
    u128::try_from(leaves).map_err(|_| ParallelHashError::MessageTooLong)
}

fn leaf_slice<'a>(
    input: Fips202BitString<'a>,
    block_size: usize,
    leaves: u128,
    index: u128,
) -> Result<Fips202BitString<'a>, ParallelHashError> {
    if index >= leaves {
        return Err(ParallelHashError::LeafOrder);
    }
    let index = usize::try_from(index).map_err(|_| ParallelHashError::LeafOrder)?;
    let start = index
        .checked_mul(block_size)
        .ok_or(ParallelHashError::MessageTooLong)?;
    let end = core::cmp::min(
        start
            .checked_add(block_size)
            .ok_or(ParallelHashError::MessageTooLong)?,
        input.as_bytes().len(),
    );
    let bytes = input
        .as_bytes()
        .get(start..end)
        .ok_or(ParallelHashError::LeafOrder)?;
    let final_leaf = u128::try_from(index)
        .ok()
        .and_then(|value| value.checked_add(1))
        == Some(leaves);
    let valid = if final_leaf {
        input.valid_bits_in_last_byte()
    } else {
        8
    };
    Fips202BitString::new(bytes, valid).map_err(|_| ParallelHashError::InvalidBitString)
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
