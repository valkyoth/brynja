use crate::Fips202BitString;

use super::{
    output::{
        HardenedSha3Error, HardenedSha3SecretOutput, Sha3PublicDeclassification, begin_secret,
        finish_secret,
    },
    owner::HardenedFips202Owner,
    sponge::{SHA3_SUFFIX, SHA3_SUFFIX_BITS},
};

macro_rules! hardened_sha3 {
    ($name:ident, $rate:expr, $output:expr, $label:literal) => {
        #[doc = concat!("Portable secret-bearing ", $label, " streaming state.")]
        ///
        /// This affine type is neither cloneable, copyable, formattable nor
        /// resettable. It owns and clears every source-declared internal byte
        /// region. Finalization requires either explicit public declassification
        /// or a caller-owned typed secret destination.
        pub struct $name {
            owner: HardenedFips202Owner<$rate>,
        }

        impl $name {
            /// Maximum complete-byte count representable by the state counter.
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

            /// Consumes the state and writes an explicitly public digest.
            pub fn finalize_public(
                mut self,
                destination: &mut [u8],
                _authority: Sha3PublicDeclassification,
            ) -> Result<(), HardenedSha3Error> {
                if destination.len() != $output {
                    return Err(HardenedSha3Error::OutputLength);
                }
                self.owner.finalize(None, SHA3_SUFFIX, SHA3_SUFFIX_BITS);
                self.owner.stage_fixed($output);
                let output = self
                    .owner
                    .staged($output)
                    .ok_or(HardenedSha3Error::OutputLength)?;
                destination.copy_from_slice(output);
                Ok(())
            }

            /// Consumes the state and transfers typed secret digest ownership.
            pub fn finalize_secret<'output>(
                mut self,
                destination: &'output mut [u8],
            ) -> Result<HardenedSha3SecretOutput<'output>, HardenedSha3Error> {
                let destination_length = destination.len();
                let mut initialization = begin_secret(destination)?;
                if destination_length != $output {
                    return Err(HardenedSha3Error::OutputLength);
                }
                self.owner.finalize(None, SHA3_SUFFIX, SHA3_SUFFIX_BITS);
                self.owner.stage_fixed($output);
                let output = self
                    .owner
                    .staged($output)
                    .ok_or(HardenedSha3Error::OutputLength)?;
                match initialization.as_mut() {
                    Some(initialization) => initialization.write(output)?,
                    None => return Err(HardenedSha3Error::SecretMemory),
                }
                finish_secret(initialization)
            }

            /// Consumes the state with one canonical final FIPS 202 bit string
            /// and writes an explicitly public digest.
            pub fn finalize_bits_public(
                mut self,
                input: Fips202BitString<'_>,
                destination: &mut [u8],
                _authority: Sha3PublicDeclassification,
            ) -> Result<(), HardenedSha3Error> {
                if destination.len() != $output {
                    return Err(HardenedSha3Error::OutputLength);
                }
                let bits = u128::try_from(input.bit_len())
                    .map_err(|_| HardenedSha3Error::MessageTooLong)?;
                self.check_additional_bits(bits)?;
                let (complete, partial) = input.split();
                self.update(complete)?;
                self.owner.finalize(partial, SHA3_SUFFIX, SHA3_SUFFIX_BITS);
                self.owner.stage_fixed($output);
                let output = self
                    .owner
                    .staged($output)
                    .ok_or(HardenedSha3Error::OutputLength)?;
                destination.copy_from_slice(output);
                Ok(())
            }

            /// Consumes the state with one canonical final FIPS 202 bit string
            /// and transfers typed secret digest ownership.
            pub fn finalize_bits_secret<'output>(
                mut self,
                input: Fips202BitString<'_>,
                destination: &'output mut [u8],
            ) -> Result<HardenedSha3SecretOutput<'output>, HardenedSha3Error> {
                let destination_length = destination.len();
                let mut initialization = begin_secret(destination)?;
                if destination_length != $output {
                    return Err(HardenedSha3Error::OutputLength);
                }
                let bits = u128::try_from(input.bit_len())
                    .map_err(|_| HardenedSha3Error::MessageTooLong)?;
                self.check_additional_bits(bits)?;
                let (complete, partial) = input.split();
                self.update(complete)?;
                self.owner.finalize(partial, SHA3_SUFFIX, SHA3_SUFFIX_BITS);
                self.owner.stage_fixed($output);
                let output = self
                    .owner
                    .staged($output)
                    .ok_or(HardenedSha3Error::OutputLength)?;
                match initialization.as_mut() {
                    Some(initialization) => initialization.write(output)?,
                    None => return Err(HardenedSha3Error::SecretMemory),
                }
                finish_secret(initialization)
            }

            /// Consumes and clears this state without producing output.
            pub fn cancel(self) {}
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

hardened_sha3!(HardenedSha3_224, 144, 28, "SHA3-224");
hardened_sha3!(HardenedSha3_256, 136, 32, "SHA3-256");
hardened_sha3!(HardenedSha3_384, 104, 48, "SHA3-384");
hardened_sha3!(HardenedSha3_512, 72, 64, "SHA3-512");
