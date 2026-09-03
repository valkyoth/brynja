use brynja_hash_sha3::{Fips202BitString, Fips202Output, HardenedCshake128, HardenedCshake256};

use crate::{
    backend::CshakeReader,
    core_state::KmacCore,
    error::KmacError,
    output::{KmacSecretOutput, KmacTag, KmacVerification},
    policy::{KmacKeyPolicy, KmacServiceStatus, tag_policy},
    verify::verify_reader,
};

macro_rules! fixed_kmac {
    ($state:ident, $backend:ty, $rate:literal, $strength:literal, $label:literal) => {
        #[doc = concat!("Secret-bearing streaming ", $label, " state.")]
        ///
        /// The state is affine and cannot be cloned or formatted. Construction
        /// absorbs the key directly into the hardened cSHAKE owner.
        pub struct $state {
            core: KmacCore<$backend, $rate, $strength>,
        }

        impl $state {
            /// Creates a production state and rejects keys below this instance's strength.
            pub fn new(key: &[u8], customization: &[u8]) -> Result<Self, KmacError> {
                let key = byte_string(key)?;
                let customization = byte_string(customization)?;
                Self::new_bits(key, customization)
            }

            /// Creates a production state over canonical arbitrary-bit inputs.
            pub fn new_bits(
                key: Fips202BitString<'_>,
                customization: Fips202BitString<'_>,
            ) -> Result<Self, KmacError> {
                KmacCore::new_bits(key, customization, true).map(|core| Self { core })
            }

            /// Creates an exact-conformance state, including empty and short keys.
            pub fn new_conformance(key: &[u8], customization: &[u8]) -> Result<Self, KmacError> {
                let key = byte_string(key)?;
                let customization = byte_string(customization)?;
                Self::new_bits_conformance(key, customization)
            }

            /// Creates an exact-conformance arbitrary-bit state.
            pub fn new_bits_conformance(
                key: Fips202BitString<'_>,
                customization: Fips202BitString<'_>,
            ) -> Result<Self, KmacError> {
                KmacCore::new_bits(key, customization, false).map(|core| Self { core })
            }

            /// Returns whether the supplied key reaches the selected strength.
            #[must_use]
            pub fn key_policy(&self) -> KmacKeyPolicy {
                self.core.key_policy()
            }

            /// Reports the current non-approved service status.
            #[must_use]
            pub const fn service_status(&self) -> KmacServiceStatus {
                KmacServiceStatus::NonApproved
            }

            /// Returns the complete message-byte count accepted after key setup.
            #[must_use]
            pub fn message_bytes(&self) -> u128 {
                self.core.message_bytes()
            }

            /// Checks an additional message byte count without mutation.
            pub fn check_additional_bytes(&self, additional: u128) -> Result<(), KmacError> {
                self.core.check_additional_bytes(additional)
            }

            /// Absorbs every message byte or rejects before observable mutation.
            pub fn update(&mut self, input: &[u8]) -> Result<(), KmacError> {
                self.core.update(input)
            }

            /// Produces a full-strength public MAC tag.
            pub fn finalize_tag<'output>(
                self,
                output: &'output mut [u8],
            ) -> Result<KmacTag<'output>, KmacError> {
                self.finish_tag(None, output, true)
            }

            /// Produces a standards-valid public tag and reports its length policy.
            pub fn finalize_tag_conformance<'output>(
                self,
                output: &'output mut [u8],
            ) -> Result<KmacTag<'output>, KmacError> {
                self.finish_tag(None, output, false)
            }

            /// Produces a full-strength tag after one final arbitrary-bit message.
            pub fn finalize_tag_bits<'output>(
                self,
                final_message: Fips202BitString<'_>,
                output: &'output mut [u8],
                valid_output_bits: u8,
            ) -> Result<KmacTag<'output>, KmacError> {
                self.finish_tag_bits(final_message, output, valid_output_bits, true)
            }

            /// Produces an exact-conformance arbitrary-bit tag.
            pub fn finalize_tag_bits_conformance<'output>(
                self,
                final_message: Fips202BitString<'_>,
                output: &'output mut [u8],
                valid_output_bits: u8,
            ) -> Result<KmacTag<'output>, KmacError> {
                self.finish_tag_bits(final_message, output, valid_output_bits, false)
            }

            /// Produces full-strength typed secret output.
            pub fn finalize_secret<'output>(
                self,
                output: &'output mut [u8],
            ) -> Result<KmacSecretOutput<'output>, KmacError> {
                let bits = byte_output_bits(output.len())?;
                let mut reader = self.core.finish_fixed(None, bits, true)?;
                reader
                    .squeeze_secret(output)
                    .map(KmacSecretOutput::new)
                    .map_err(KmacError::from)
            }

            /// Produces typed secret output after one final arbitrary-bit message.
            pub fn finalize_secret_bits<'output>(
                self,
                final_message: Fips202BitString<'_>,
                output: Fips202Output<'output>,
            ) -> Result<KmacSecretOutput<'output>, KmacError> {
                let bits =
                    u128::try_from(output.bit_len()).map_err(|_| KmacError::OutputTooLong)?;
                let reader = self.core.finish_fixed(Some(final_message), bits, true)?;
                CshakeReader::squeeze_final_bits_secret(reader, output)
                    .map(KmacSecretOutput::new)
                    .map_err(KmacError::from)
            }

            /// Produces exact-conformance typed secret arbitrary-bit output.
            pub fn finalize_secret_bits_conformance<'output>(
                self,
                final_message: Fips202BitString<'_>,
                output: Fips202Output<'output>,
            ) -> Result<KmacSecretOutput<'output>, KmacError> {
                let bits =
                    u128::try_from(output.bit_len()).map_err(|_| KmacError::OutputTooLong)?;
                let reader = self.core.finish_fixed(Some(final_message), bits, false)?;
                CshakeReader::squeeze_final_bits_secret(reader, output)
                    .map(KmacSecretOutput::new)
                    .map_err(KmacError::from)
            }

            /// Verifies one full-strength byte tag in constant work for its public length.
            pub fn verify(self, candidate: &[u8]) -> Result<KmacVerification, KmacError> {
                let candidate = byte_string(candidate)?;
                self.verify_inner(None, candidate, true)
            }

            /// Verifies any standards-valid byte tag, including short conformance values.
            pub fn verify_conformance(
                self,
                candidate: &[u8],
            ) -> Result<KmacVerification, KmacError> {
                let candidate = byte_string(candidate)?;
                self.verify_inner(None, candidate, false)
            }

            /// Verifies a full-strength arbitrary-bit tag after a final bit message.
            pub fn verify_bits(
                self,
                final_message: Fips202BitString<'_>,
                candidate: Fips202BitString<'_>,
            ) -> Result<KmacVerification, KmacError> {
                self.verify_inner(Some(final_message), candidate, true)
            }

            /// Verifies an exact-conformance arbitrary-bit tag.
            pub fn verify_bits_conformance(
                self,
                final_message: Fips202BitString<'_>,
                candidate: Fips202BitString<'_>,
            ) -> Result<KmacVerification, KmacError> {
                self.verify_inner(Some(final_message), candidate, false)
            }

            /// Consumes and clears this state without producing output.
            pub fn cancel(self) {}

            fn finish_tag<'output>(
                self,
                final_message: Option<Fips202BitString<'_>>,
                output: &'output mut [u8],
                production: bool,
            ) -> Result<KmacTag<'output>, KmacError> {
                let bits = byte_output_bits(output.len())?;
                let policy = tag_policy(bits, $strength);
                let mut reader = self.core.finish_fixed(final_message, bits, production)?;
                CshakeReader::squeeze_public(&mut reader, output).map_err(KmacError::from)?;
                Ok(KmacTag::new(output, bits, policy))
            }

            fn finish_tag_bits<'output>(
                self,
                final_message: Fips202BitString<'_>,
                output: &'output mut [u8],
                valid_output_bits: u8,
                production: bool,
            ) -> Result<KmacTag<'output>, KmacError> {
                let bits = exact_output_bits(output.len(), valid_output_bits)?;
                let policy = tag_policy(bits, $strength);
                let reader = self
                    .core
                    .finish_fixed(Some(final_message), bits, production)?;
                let destination = Fips202Output::new(&mut *output, valid_output_bits)
                    .map_err(|_| KmacError::InvalidBitString)?;
                CshakeReader::squeeze_final_bits_public(reader, destination)
                    .map_err(KmacError::from)?;
                Ok(KmacTag::new(output, bits, policy))
            }

            fn verify_inner(
                self,
                final_message: Option<Fips202BitString<'_>>,
                candidate: Fips202BitString<'_>,
                production: bool,
            ) -> Result<KmacVerification, KmacError> {
                let bits =
                    u128::try_from(candidate.bit_len()).map_err(|_| KmacError::OutputTooLong)?;
                let reader = self.core.finish_fixed(final_message, bits, production)?;
                verify_reader(reader, candidate)
            }
        }
    };
}

fixed_kmac!(Kmac128, HardenedCshake128, 168, 128, "KMAC128");
fixed_kmac!(Kmac256, HardenedCshake256, 136, 256, "KMAC256");

fn byte_string(input: &[u8]) -> Result<Fips202BitString<'_>, KmacError> {
    let valid = if input.is_empty() { 0 } else { 8 };
    Fips202BitString::new(input, valid).map_err(|_| KmacError::InvalidBitString)
}

fn byte_output_bits(length: usize) -> Result<u128, KmacError> {
    u128::try_from(length)
        .ok()
        .and_then(|value| value.checked_mul(8))
        .ok_or(KmacError::OutputTooLong)
}

fn exact_output_bits(length: usize, valid: u8) -> Result<u128, KmacError> {
    if length == 0 {
        return if valid == 0 {
            Ok(0)
        } else {
            Err(KmacError::InvalidBitString)
        };
    }
    if !(1..=8).contains(&valid) {
        return Err(KmacError::InvalidBitString);
    }
    u128::try_from(length.saturating_sub(1))
        .ok()
        .and_then(|value| value.checked_mul(8))
        .and_then(|value| value.checked_add(u128::from(valid)))
        .ok_or(KmacError::OutputTooLong)
}
