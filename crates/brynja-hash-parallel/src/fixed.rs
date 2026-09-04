use brynja_hash_sha3::{Fips202BitString, Fips202Output};

use crate::{
    ParallelHashError, ParallelHashPublicDeclassification, ParallelHashSecretOutput,
    backend::Strength,
    core_state::{ParallelCore, byte_string, finish_public, finish_public_bits, output_bits},
};

macro_rules! common {
    ($state:ident, $strength:expr) => {
        impl<'workspace> $state<'workspace> {
            /// Creates a byte-oriented state. The workspace length is `B`.
            pub fn new(
                workspace: &'workspace mut [u8],
                customization: &[u8],
            ) -> Result<Self, ParallelHashError> {
                Self::new_bits(workspace, byte_string(customization)?)
            }

            /// Creates a state with canonical arbitrary-bit customization.
            pub fn new_bits(
                workspace: &'workspace mut [u8],
                customization: Fips202BitString<'_>,
            ) -> Result<Self, ParallelHashError> {
                ParallelCore::new(workspace, $strength, customization).map(|core| Self { core })
            }

            /// Returns the selected block size `B` in bytes.
            #[must_use]
            pub fn block_size(&self) -> usize {
                self.core.block_size()
            }

            /// Returns the number of completed leaves.
            #[must_use]
            pub fn leaf_count(&self) -> u128 {
                self.core.leaf_count()
            }

            /// Absorbs every complete input byte.
            pub fn update(&mut self, input: &[u8]) -> Result<(), ParallelHashError> {
                self.core.update(input)
            }

            /// Clears the construction and its complete caller workspace.
            pub fn cancel(&mut self) {
                self.core.cancel();
            }
        }
    };
}

macro_rules! ordinary {
    ($state:ident, $strength:expr, $label:literal) => {
        #[doc = concat!("Allocation-free streaming ", $label, " state for public input.")]
        pub struct $state<'workspace> {
            core: ParallelCore<'workspace>,
        }
        common!($state, $strength);

        impl $state<'_> {
            /// Finalizes complete-byte input into a fixed public output.
            pub fn finalize(&mut self, output: &mut [u8]) -> Result<(), ParallelHashError> {
                let bits = output_bits(output.len())?;
                self.core.finalize_input(None)?;
                finish_public(&mut self.core.finish(None, bits)?, output)
            }

            /// Finalizes after one canonical arbitrary-bit suffix.
            pub fn finalize_bits(
                &mut self,
                tail: Fips202BitString<'_>,
                output: Fips202Output<'_>,
            ) -> Result<(), ParallelHashError> {
                let bits = u128::try_from(output.bit_len())
                    .map_err(|_| ParallelHashError::OutputTooLong)?;
                self.core.finalize_input(Some(tail))?;
                finish_public_bits(self.core.finish(None, bits)?, output)
            }
        }
    };
}

macro_rules! hardened {
    ($state:ident, $strength:expr, $label:literal) => {
        #[doc = concat!("Allocation-free secret-bearing ", $label, " state.")]
        pub struct $state<'workspace> {
            core: ParallelCore<'workspace>,
        }
        common!($state, $strength);

        impl $state<'_> {
            /// Finalizes complete-byte input into typed secret output.
            pub fn finalize_secret<'a>(
                &mut self,
                output: &'a mut [u8],
            ) -> Result<ParallelHashSecretOutput<'a>, ParallelHashError> {
                let bits = output_bits(output.len())?;
                self.core.finalize_input(None)?;
                self.core
                    .finish(None, bits)?
                    .squeeze_secret(output)
                    .map(ParallelHashSecretOutput::new)
                    .map_err(ParallelHashError::from)
            }

            /// Finalizes arbitrary-bit input and output with typed ownership.
            pub fn finalize_secret_bits<'a>(
                &mut self,
                tail: Fips202BitString<'_>,
                output: Fips202Output<'a>,
            ) -> Result<ParallelHashSecretOutput<'a>, ParallelHashError> {
                let bits = u128::try_from(output.bit_len())
                    .map_err(|_| ParallelHashError::OutputTooLong)?;
                self.core.finalize_input(Some(tail))?;
                self.core
                    .finish(None, bits)?
                    .squeeze_final_secret(output)
                    .map(ParallelHashSecretOutput::new)
                    .map_err(ParallelHashError::from)
            }

            /// Explicitly declassifies a fixed complete-byte output.
            pub fn finalize_public(
                &mut self,
                output: &mut [u8],
                _authority: ParallelHashPublicDeclassification,
            ) -> Result<(), ParallelHashError> {
                let bits = output_bits(output.len())?;
                self.core.finalize_input(None)?;
                finish_public(&mut self.core.finish(None, bits)?, output)
            }
        }
    };
}

ordinary!(ParallelHash128, Strength::Bits128, "ParallelHash128");
ordinary!(ParallelHash256, Strength::Bits256, "ParallelHash256");
hardened!(
    HardenedParallelHash128,
    Strength::Bits128,
    "ParallelHash128"
);
hardened!(
    HardenedParallelHash256,
    Strength::Bits256,
    "ParallelHash256"
);
