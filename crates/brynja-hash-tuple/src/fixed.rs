use brynja_hash_sha3::{Fips202BitString, Fips202Output};

use crate::{
    TupleHashError, TupleHashPublicDeclassification, TupleHashSecretOutput,
    core_state::{TupleCore, byte_string, output_bits},
    item::TupleItemWriter,
};

macro_rules! tuple_state_common {
    ($state:ident, $strength:literal) => {
        impl $state {
            /// Creates a byte-oriented state with the supplied customization.
            pub fn new(customization: &[u8]) -> Result<Self, TupleHashError> {
                Self::new_bits(byte_string(customization)?)
            }

            /// Creates a state with canonical arbitrary-bit customization.
            pub fn new_bits(customization: Fips202BitString<'_>) -> Result<Self, TupleHashError> {
                TupleCore::new($strength, customization).map(|core| Self { core })
            }

            /// Returns the number of complete tuple items accepted.
            #[must_use]
            pub fn item_count(&self) -> u128 {
                self.core.item_count()
            }

            /// Appends one complete byte-oriented item.
            pub fn push_item(&mut self, item: &[u8]) -> Result<(), TupleHashError> {
                self.push_item_bits(byte_string(item)?)
            }

            /// Appends one complete canonical arbitrary-bit item.
            pub fn push_item_bits(
                &mut self,
                item: Fips202BitString<'_>,
            ) -> Result<(), TupleHashError> {
                self.core.push_item(item)
            }

            /// Begins one item whose declared bit length must be consumed exactly.
            pub fn begin_item(
                &mut self,
                bit_length: u128,
            ) -> Result<TupleItemWriter<'_>, TupleHashError> {
                self.core.begin_item(bit_length)?;
                Ok(TupleItemWriter::new(&mut self.core, bit_length))
            }

            /// Consumes and clears this state without producing output.
            pub fn cancel(self) {}
        }
    };
}

macro_rules! ordinary_fixed {
    ($state:ident, $strength:literal, $label:literal) => {
        #[doc = concat!("Streaming ", $label, " state for public/unkeyed tuples.")]
        pub struct $state {
            core: TupleCore,
        }
        tuple_state_common!($state, $strength);

        impl $state {
            /// Produces a fixed byte-oriented public digest.
            pub fn finalize(mut self, output: &mut [u8]) -> Result<(), TupleHashError> {
                let bits = output_bits(output.len())?;
                let mut reader = self.core.finish(bits)?;
                reader.squeeze_public(output).map_err(TupleHashError::from)
            }

            /// Produces a fixed canonical arbitrary-bit public digest.
            pub fn finalize_bits(
                mut self,
                output: Fips202Output<'_>,
            ) -> Result<(), TupleHashError> {
                let bits =
                    u128::try_from(output.bit_len()).map_err(|_| TupleHashError::OutputTooLong)?;
                self.core
                    .finish(bits)?
                    .squeeze_final_public(output)
                    .map_err(TupleHashError::from)
            }
        }
    };
}

macro_rules! hardened_fixed {
    ($state:ident, $strength:literal, $label:literal) => {
        #[doc = concat!("Secret-bearing streaming ", $label, " state.")]
        pub struct $state {
            core: TupleCore,
        }
        tuple_state_common!($state, $strength);

        impl $state {
            /// Produces output with typed secret ownership.
            pub fn finalize_secret<'a>(
                mut self,
                output: &'a mut [u8],
            ) -> Result<TupleHashSecretOutput<'a>, TupleHashError> {
                let bits = output_bits(output.len())?;
                let mut reader = self.core.finish(bits)?;
                reader
                    .squeeze_secret(output)
                    .map(TupleHashSecretOutput::new)
                    .map_err(TupleHashError::from)
            }

            /// Produces arbitrary-bit output with typed secret ownership.
            pub fn finalize_secret_bits<'a>(
                mut self,
                output: Fips202Output<'a>,
            ) -> Result<TupleHashSecretOutput<'a>, TupleHashError> {
                let bits =
                    u128::try_from(output.bit_len()).map_err(|_| TupleHashError::OutputTooLong)?;
                self.core
                    .finish(bits)?
                    .squeeze_final_secret(output)
                    .map(TupleHashSecretOutput::new)
                    .map_err(TupleHashError::from)
            }

            /// Explicitly declassifies one fixed byte-oriented output.
            pub fn finalize_public(
                mut self,
                output: &mut [u8],
                _authority: TupleHashPublicDeclassification,
            ) -> Result<(), TupleHashError> {
                let bits = output_bits(output.len())?;
                let mut reader = self.core.finish(bits)?;
                reader.squeeze_public(output).map_err(TupleHashError::from)
            }

            /// Explicitly declassifies one fixed arbitrary-bit output.
            pub fn finalize_public_bits(
                mut self,
                output: Fips202Output<'_>,
                _authority: TupleHashPublicDeclassification,
            ) -> Result<(), TupleHashError> {
                let bits =
                    u128::try_from(output.bit_len()).map_err(|_| TupleHashError::OutputTooLong)?;
                self.core
                    .finish(bits)?
                    .squeeze_final_public(output)
                    .map_err(TupleHashError::from)
            }
        }
    };
}

ordinary_fixed!(TupleHash128, 128, "TupleHash128");
ordinary_fixed!(TupleHash256, 256, "TupleHash256");
hardened_fixed!(HardenedTupleHash128, 128, "TupleHash128");
hardened_fixed!(HardenedTupleHash256, 256, "TupleHash256");
