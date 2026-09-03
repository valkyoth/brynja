use crate::{Fips202BitString, Fips202Output, sp800185::absorb_cshake_prefix};

use super::{
    output::{
        HardenedSha3Error, HardenedSha3SecretOutput, Sha3PublicDeclassification, begin_secret,
        finish_secret,
    },
    owner::HardenedFips202Owner,
    sponge::{SHAKE_SUFFIX, SHAKE_SUFFIX_BITS},
};

const CSHAKE_SUFFIX: u8 = 0x04;
const CSHAKE_SUFFIX_BITS: u8 = 3;

macro_rules! hardened_cshake {
    ($state:ident, $reader:ident, $rate:literal, $label:literal) => {
        #[doc = concat!("Portable secret-bearing ", $label, " absorbing state.")]
        ///
        /// All crate-owned sponge, prefix, partial-input, permutation, padding,
        /// and output staging storage is compiler-resistantly cleared.
        pub struct $state {
            owner: HardenedFips202Owner<$rate>,
        }

        impl $state {
            /// Maximum complete-byte count representable by the owner counter.
            pub const MAX_MESSAGE_BYTES: u128 = u128::MAX;

            /// Creates a byte-oriented hardened state.
            pub fn new(
                function_name: &[u8],
                customization: &[u8],
            ) -> Result<Self, HardenedSha3Error> {
                let function_name = byte_string(function_name)?;
                let customization = byte_string(customization)?;
                Self::new_bits(function_name, customization)
            }

            /// Creates a hardened state over canonical arbitrary-bit `N` and `S`.
            pub fn new_bits(
                function_name: Fips202BitString<'_>,
                customization: Fips202BitString<'_>,
            ) -> Result<Self, HardenedSha3Error> {
                let mut owner = HardenedFips202Owner::<$rate>::new();
                let customized =
                    absorb_cshake_prefix($rate, function_name, customization, |bytes| {
                        owner.update(bytes)
                    })
                    .map_err(|()| HardenedSha3Error::MessageTooLong)?;
                owner.remember_cshake_setup(customized);
                Ok(Self { owner })
            }

            /// Returns the complete message bytes accepted after setup.
            #[must_use]
            pub fn message_bytes(&self) -> u128 {
                self.owner.cshake_message_bytes()
            }

            /// Checks an additional byte count without mutation.
            pub fn check_additional_bytes(
                &self,
                additional: u128,
            ) -> Result<(), HardenedSha3Error> {
                self.owner
                    .check_message_bytes(additional)
                    .map_err(|()| HardenedSha3Error::MessageTooLong)
            }

            /// Checks an additional exact bit count without mutation.
            pub fn check_additional_bits(&self, additional: u128) -> Result<(), HardenedSha3Error> {
                self.owner
                    .check_message_bits(additional)
                    .map_err(|()| HardenedSha3Error::MessageTooLong)
            }

            /// Absorbs every byte or rejects before observable mutation.
            pub fn update(&mut self, input: &[u8]) -> Result<(), HardenedSha3Error> {
                self.owner
                    .update(input)
                    .map_err(|()| HardenedSha3Error::MessageTooLong)
            }

            /// Consumes absorption and returns a hardened incremental reader.
            #[must_use]
            pub fn finalize_xof(mut self) -> $reader {
                self.finish(None);
                $reader { owner: self.owner }
            }

            /// Consumes absorption after one final canonical message bit string.
            pub fn finalize_bits_xof(
                mut self,
                input: Fips202BitString<'_>,
            ) -> Result<$reader, HardenedSha3Error> {
                let bits = u128::try_from(input.bit_len())
                    .map_err(|_| HardenedSha3Error::MessageTooLong)?;
                self.check_additional_bits(bits)?;
                let (complete, partial) = input.split();
                self.update(complete)?;
                self.finish(partial);
                Ok($reader { owner: self.owner })
            }

            /// Produces one explicitly declassified fixed public output.
            pub fn finalize_public(
                self,
                output: &mut [u8],
                authority: Sha3PublicDeclassification,
            ) -> Result<(), HardenedSha3Error> {
                self.finalize_xof().squeeze_public(output, authority)
            }

            /// Produces one fixed output with typed secret ownership.
            pub fn finalize_secret<'output>(
                self,
                output: &'output mut [u8],
            ) -> Result<HardenedSha3SecretOutput<'output>, HardenedSha3Error> {
                self.finalize_xof().squeeze_secret(output)
            }

            /// Consumes and clears this state without output.
            pub fn cancel(self) {}

            fn finish(&mut self, partial: Option<(u8, u8)>) {
                if self.owner.cshake_is_customized() {
                    self.owner
                        .finalize(partial, CSHAKE_SUFFIX, CSHAKE_SUFFIX_BITS);
                } else {
                    self.owner
                        .finalize(partial, SHAKE_SUFFIX, SHAKE_SUFFIX_BITS);
                }
                self.owner.wipe_cshake_metadata();
            }
        }

        #[doc = concat!("Portable secret-bearing ", $label, " output reader.")]
        pub struct $reader {
            owner: HardenedFips202Owner<$rate>,
        }

        impl $reader {
            /// Maximum complete-byte count representable by the output counter.
            pub const MAX_OUTPUT_BYTES: u128 = u128::MAX;

            /// Returns the complete output byte count emitted so far.
            #[must_use]
            pub fn output_bytes(&self) -> u128 {
                self.owner.output_bytes()
            }

            /// Checks an additional byte count without mutation.
            pub fn check_additional_bytes(
                &self,
                additional: u128,
            ) -> Result<(), HardenedSha3Error> {
                self.owner
                    .check_output_bytes(additional)
                    .map_err(|()| HardenedSha3Error::OutputTooLong)
            }

            /// Checks an additional bit count without mutation.
            pub fn check_additional_bits(&self, additional: u128) -> Result<(), HardenedSha3Error> {
                self.owner
                    .check_output_bits(additional)
                    .map_err(|()| HardenedSha3Error::OutputTooLong)
            }

            /// Writes an explicitly declassified public fragment.
            pub fn squeeze_public(
                &mut self,
                output: &mut [u8],
                authority: Sha3PublicDeclassification,
            ) -> Result<(), HardenedSha3Error> {
                self.owner.squeeze_public(output, authority)
            }

            /// Writes a fragment and transfers typed secret ownership.
            pub fn squeeze_secret<'output>(
                &mut self,
                output: &'output mut [u8],
            ) -> Result<HardenedSha3SecretOutput<'output>, HardenedSha3Error> {
                let length = output.len();
                let mut initialization = begin_secret(output)?;
                match initialization.as_mut() {
                    Some(initialization) => self.owner.squeeze_secret(initialization, length)?,
                    None => self
                        .owner
                        .check_output_bytes(0)
                        .map_err(|()| HardenedSha3Error::OutputTooLong)?,
                }
                finish_secret(initialization)
            }

            /// Consumes the reader after a final public arbitrary-bit output.
            pub fn squeeze_final_bits_public(
                mut self,
                output: Fips202Output<'_>,
                authority: Sha3PublicDeclassification,
            ) -> Result<(), HardenedSha3Error> {
                self.owner.squeeze_final_bits_public(output, authority)
            }

            /// Consumes the reader after a final secret arbitrary-bit output.
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

            /// Consumes and clears this reader without more output.
            pub fn cancel(self) {}
        }
    };
}

hardened_cshake!(HardenedCshake128, HardenedCshake128Reader, 168, "cSHAKE128");
hardened_cshake!(HardenedCshake256, HardenedCshake256Reader, 136, "cSHAKE256");

fn byte_string(input: &[u8]) -> Result<Fips202BitString<'_>, HardenedSha3Error> {
    let valid = if input.is_empty() { 0 } else { 8 };
    Fips202BitString::new(input, valid).map_err(|_| HardenedSha3Error::MessageTooLong)
}
