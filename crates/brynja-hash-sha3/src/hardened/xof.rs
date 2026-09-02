use crate::{Fips202BitString, Fips202Output};

use super::{
    output::{
        HardenedSha3Error, HardenedSha3SecretOutput, Sha3PublicDeclassification, begin_secret,
        finish_secret,
    },
    owner::HardenedFips202Owner,
    sponge::{SHAKE_SUFFIX, SHAKE_SUFFIX_BITS},
};

macro_rules! hardened_shake {
    ($state:ident, $reader:ident, $rate:expr, $label:literal) => {
        #[doc = concat!("Portable secret-bearing ", $label, " absorbing state.")]
        ///
        /// Finalization consumes this state. It owns and clears every
        /// source-declared sponge, buffer, counter, suffix, padding, and
        /// permutation-scratch region.
        pub struct $state {
            owner: HardenedFips202Owner<$rate>,
        }

        impl $state {
            /// Maximum complete-byte count representable by the input counter.
            pub const MAX_MESSAGE_BYTES: u128 = u128::MAX;

            #[doc = concat!("Creates an empty hardened ", $label, " state.")]
            #[must_use]
            pub fn new() -> Self {
                Self {
                    owner: HardenedFips202Owner::new(),
                }
            }

            /// Returns the number of accepted complete message bytes.
            #[must_use]
            pub fn message_bytes(&self) -> u128 {
                self.owner.message_bytes()
            }

            /// Checks a byte count without mutating this state.
            pub fn check_additional_bytes(
                &self,
                additional: u128,
            ) -> Result<(), HardenedSha3Error> {
                self.owner
                    .check_message_bytes(additional)
                    .map_err(|()| HardenedSha3Error::MessageTooLong)
            }

            /// Checks an exact bit count without mutating this state.
            pub fn check_additional_bits(&self, additional: u128) -> Result<(), HardenedSha3Error> {
                self.owner
                    .check_message_bits(additional)
                    .map_err(|()| HardenedSha3Error::MessageTooLong)
            }

            /// Absorbs the complete byte slice or rejects without mutation.
            pub fn update(&mut self, input: &[u8]) -> Result<(), HardenedSha3Error> {
                self.owner
                    .update(input)
                    .map_err(|()| HardenedSha3Error::MessageTooLong)
            }

            /// Consumes absorption and creates a hardened incremental reader.
            #[must_use]
            pub fn finalize_xof(mut self) -> $reader {
                self.owner.finalize(None, SHAKE_SUFFIX, SHAKE_SUFFIX_BITS);
                $reader { owner: self.owner }
            }

            /// Consumes absorption after one final canonical bit string.
            pub fn finalize_bits_xof(
                mut self,
                input: Fips202BitString<'_>,
            ) -> Result<$reader, HardenedSha3Error> {
                let bits = u128::try_from(input.bit_len())
                    .map_err(|_| HardenedSha3Error::MessageTooLong)?;
                self.check_additional_bits(bits)?;
                let (complete, partial) = input.split();
                self.update(complete)?;
                self.owner
                    .finalize(partial, SHAKE_SUFFIX, SHAKE_SUFFIX_BITS);
                Ok($reader { owner: self.owner })
            }

            /// Consumes and clears this state without producing output.
            pub fn cancel(self) {}
        }

        impl Default for $state {
            fn default() -> Self {
                Self::new()
            }
        }

        #[doc = concat!("Portable secret-bearing ", $label, " output reader.")]
        ///
        /// Every read requires explicit public declassification or transfers
        /// typed secret ownership of the complete caller destination.
        pub struct $reader {
            owner: HardenedFips202Owner<$rate>,
        }

        impl $reader {
            /// Maximum complete-byte count representable by the output counter.
            pub const MAX_OUTPUT_BYTES: u128 = u128::MAX;

            /// Returns the number of complete bytes emitted so far.
            #[must_use]
            pub fn output_bytes(&self) -> u128 {
                self.owner.output_bytes()
            }

            /// Checks a byte count without mutating this reader.
            pub fn check_additional_bytes(
                &self,
                additional: u128,
            ) -> Result<(), HardenedSha3Error> {
                self.owner
                    .check_output_bytes(additional)
                    .map_err(|()| HardenedSha3Error::OutputTooLong)
            }

            /// Checks an exact bit count without mutating this reader.
            pub fn check_additional_bits(&self, additional: u128) -> Result<(), HardenedSha3Error> {
                self.owner
                    .check_output_bits(additional)
                    .map_err(|()| HardenedSha3Error::OutputTooLong)
            }

            /// Writes one explicitly declassified public output fragment.
            pub fn squeeze_public(
                &mut self,
                destination: &mut [u8],
                authority: Sha3PublicDeclassification,
            ) -> Result<(), HardenedSha3Error> {
                self.owner.squeeze_public(destination, authority)
            }

            /// Writes one fragment and transfers typed secret ownership.
            pub fn squeeze_secret<'output>(
                &mut self,
                destination: &'output mut [u8],
            ) -> Result<HardenedSha3SecretOutput<'output>, HardenedSha3Error> {
                let destination_length = destination.len();
                let mut initialization = begin_secret(destination)?;
                match initialization.as_mut() {
                    Some(initialization) => {
                        self.owner
                            .squeeze_secret(initialization, destination_length)?;
                    }
                    None => self
                        .owner
                        .check_output_bytes(0)
                        .map_err(|()| HardenedSha3Error::OutputTooLong)?,
                }
                finish_secret(initialization)
            }

            /// Consumes the reader after one final arbitrary-bit public output.
            pub fn squeeze_final_bits_public(
                mut self,
                output: Fips202Output<'_>,
                authority: Sha3PublicDeclassification,
            ) -> Result<(), HardenedSha3Error> {
                self.owner.squeeze_final_bits_public(output, authority)
            }

            /// Consumes the reader after one final arbitrary-bit secret output.
            pub fn squeeze_final_bits_secret<'output>(
                mut self,
                output: Fips202Output<'output>,
            ) -> Result<HardenedSha3SecretOutput<'output>, HardenedSha3Error> {
                let (destination, valid) = output.into_parts();
                let destination_length = destination.len();
                let mut initialization = begin_secret(destination)?;
                match initialization.as_mut() {
                    Some(initialization) => self.owner.squeeze_final_bits_secret(
                        destination_length,
                        valid,
                        initialization,
                    )?,
                    None => self
                        .owner
                        .check_output_bits(0)
                        .map_err(|()| HardenedSha3Error::OutputTooLong)?,
                }
                finish_secret(initialization)
            }

            /// Consumes and clears this reader without producing more output.
            pub fn cancel(self) {}
        }
    };
}

hardened_shake!(HardenedShake128, HardenedShake128Reader, 168, "SHAKE128");
hardened_shake!(HardenedShake256, HardenedShake256Reader, 136, "SHAKE256");
