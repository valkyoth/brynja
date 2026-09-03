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

#[derive(Clone, Copy, Eq, PartialEq)]
enum CshakeLifecycle {
    Live,
    Vacated,
}

macro_rules! hardened_cshake {
    ($state:ident, $reader:ident, $rate:literal, $label:literal) => {
        #[doc = concat!("Portable secret-bearing ", $label, " absorbing state.")]
        ///
        /// All crate-owned sponge, prefix, partial-input, permutation, padding,
        /// and output staging storage is compiler-resistantly cleared.
        pub struct $state {
            owner: HardenedFips202Owner<$rate>,
            lifecycle: CshakeLifecycle,
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
                Ok(Self {
                    owner,
                    lifecycle: CshakeLifecycle::Live,
                })
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
                self.ensure_live()?;
                self.owner
                    .check_message_bytes(additional)
                    .map_err(|()| HardenedSha3Error::MessageTooLong)
            }

            /// Checks an additional exact bit count without mutation.
            pub fn check_additional_bits(&self, additional: u128) -> Result<(), HardenedSha3Error> {
                self.ensure_live()?;
                self.owner
                    .check_message_bits(additional)
                    .map_err(|()| HardenedSha3Error::MessageTooLong)
            }

            /// Absorbs every byte or rejects before observable mutation.
            pub fn update(&mut self, input: &[u8]) -> Result<(), HardenedSha3Error> {
                self.ensure_live()?;
                self.owner
                    .update(input)
                    .map_err(|()| HardenedSha3Error::MessageTooLong)
            }

            /// Consumes absorption and returns a hardened incremental reader.
            pub fn finalize_xof(mut self) -> Result<$reader, HardenedSha3Error> {
                self.finalize_xof_erasing_source()
            }

            /// Consumes absorption after one final canonical message bit string.
            pub fn finalize_bits_xof(
                mut self,
                input: Fips202BitString<'_>,
            ) -> Result<$reader, HardenedSha3Error> {
                self.finalize_bits_xof_erasing_source(input)
            }

            /// Finalizes in place and compiler-resistantly clears the vacated
            /// source owner before returning its incremental reader.
            ///
            /// This transition exists for hardened constructions that embed
            /// cSHAKE inline and must erase that exact source allocation.
            #[doc(hidden)]
            pub fn finalize_xof_erasing_source(&mut self) -> Result<$reader, HardenedSha3Error> {
                self.ensure_live()?;
                self.lifecycle = CshakeLifecycle::Vacated;
                self.finish(None);
                Ok(self.take_reader_erasing_source())
            }

            /// Finalizes a final bit string in place and clears the vacated
            /// source owner before returning its incremental reader.
            #[doc(hidden)]
            pub fn finalize_bits_xof_erasing_source(
                &mut self,
                input: Fips202BitString<'_>,
            ) -> Result<$reader, HardenedSha3Error> {
                self.ensure_live()?;
                let bits = u128::try_from(input.bit_len())
                    .map_err(|_| HardenedSha3Error::MessageTooLong)?;
                self.check_additional_bits(bits)?;
                let (complete, partial) = input.split();
                self.update(complete)?;
                self.lifecycle = CshakeLifecycle::Vacated;
                self.finish(partial);
                Ok(self.take_reader_erasing_source())
            }

            /// Compiler-resistantly clears this embedded construction owner
            /// in place. This is reserved for hardened composition cleanup.
            #[doc(hidden)]
            pub fn wipe_in_place(&mut self) {
                self.lifecycle = CshakeLifecycle::Vacated;
                self.owner.wipe();
            }

            /// Produces one explicitly declassified fixed public output.
            pub fn finalize_public(
                self,
                output: &mut [u8],
                authority: Sha3PublicDeclassification,
            ) -> Result<(), HardenedSha3Error> {
                self.finalize_xof()?.squeeze_public(output, authority)
            }

            /// Produces one fixed output with typed secret ownership.
            pub fn finalize_secret<'output>(
                self,
                output: &'output mut [u8],
            ) -> Result<HardenedSha3SecretOutput<'output>, HardenedSha3Error> {
                self.finalize_xof()?.squeeze_secret(output)
            }

            /// Consumes and clears this state without output.
            pub fn cancel(self) {}

            fn ensure_live(&self) -> Result<(), HardenedSha3Error> {
                if self.lifecycle == CshakeLifecycle::Live {
                    Ok(())
                } else {
                    Err(HardenedSha3Error::StateConsumed)
                }
            }

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

            #[inline(never)]
            fn take_reader_erasing_source(&mut self) -> $reader {
                let live =
                    core::mem::replace(&mut self.owner, HardenedFips202Owner::<$rate>::new());
                self.owner.wipe();
                $reader { owner: live }
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

#[cfg(test)]
mod tests {
    use super::{CshakeLifecycle, HardenedCshake128, HardenedCshake256};
    use crate::{
        Fips202BitString,
        hardened::{HardenedSha3Error, owner::HardenedFips202Owner},
    };

    fn is_cleared<const RATE: usize>(owner: &HardenedFips202Owner<RATE>) -> bool {
        owner.sponge_lanes.iter().all(|byte| *byte == 0)
            && owner.partial_input.iter().all(|byte| *byte == 0)
            && owner.message_length.iter().all(|byte| *byte == 0)
            && owner.output_length.iter().all(|byte| *byte == 0)
            && owner.cshake_setup_length.iter().all(|byte| *byte == 0)
            && owner.cshake_domain.iter().all(|byte| *byte == 0)
            && owner.phase.iter().all(|byte| *byte == 0)
            && owner.suffix_staging.iter().all(|byte| *byte == 0)
            && owner.padding_block.iter().all(|byte| *byte == 0)
            && owner.squeeze_staging.iter().all(|byte| *byte == 0)
            && owner.permutation_columns.iter().all(|byte| *byte == 0)
            && owner.permutation_theta.iter().all(|byte| *byte == 0)
            && owner.permutation_rearranged.iter().all(|byte| *byte == 0)
    }

    #[test]
    fn in_place_reader_transition_clears_exact_source_owner() {
        let cshake128 = HardenedCshake128::new(b"KMAC", b"source wipe");
        assert!(cshake128.is_ok());
        let Ok(mut cshake128) = cshake128 else {
            return;
        };
        assert_eq!(cshake128.update(b"secret-derived state"), Ok(()));
        let reader128 = cshake128.finalize_xof_erasing_source();
        assert!(reader128.is_ok());
        let Ok(reader128) = reader128 else {
            return;
        };
        assert!(is_cleared(&cshake128.owner));
        assert!(cshake128.lifecycle == CshakeLifecycle::Vacated);
        assert_eq!(
            cshake128.check_additional_bytes(0),
            Err(HardenedSha3Error::StateConsumed)
        );
        assert_eq!(
            cshake128.check_additional_bits(0),
            Err(HardenedSha3Error::StateConsumed)
        );
        assert_eq!(
            cshake128.update(b"second"),
            Err(HardenedSha3Error::StateConsumed)
        );
        assert!(matches!(
            cshake128.finalize_xof_erasing_source(),
            Err(HardenedSha3Error::StateConsumed)
        ));
        reader128.cancel();

        let cshake256 = HardenedCshake256::new(b"KMAC", b"source wipe");
        assert!(cshake256.is_ok());
        let Ok(mut cshake256) = cshake256 else {
            return;
        };
        let tail = Fips202BitString::new(&[0b0000_0101], 3);
        assert!(tail.is_ok());
        let Ok(tail) = tail else {
            return;
        };
        let reader256 = cshake256.finalize_bits_xof_erasing_source(tail);
        assert!(reader256.is_ok());
        let Ok(reader256) = reader256 else {
            return;
        };
        assert!(is_cleared(&cshake256.owner));
        assert!(cshake256.lifecycle == CshakeLifecycle::Vacated);
        assert_eq!(
            cshake256.update(b"second"),
            Err(HardenedSha3Error::StateConsumed)
        );
        assert!(matches!(
            cshake256.finalize_bits_xof_erasing_source(tail),
            Err(HardenedSha3Error::StateConsumed)
        ));
        reader256.cancel();
    }

    #[test]
    fn explicit_wipe_is_an_irreversible_terminal_transition() {
        let cshake128 = HardenedCshake128::new(b"KMAC", b"explicit wipe");
        assert!(cshake128.is_ok());
        let Ok(mut cshake128) = cshake128 else {
            return;
        };
        assert_eq!(cshake128.update(b"secret-derived state"), Ok(()));
        cshake128.wipe_in_place();
        assert!(is_cleared(&cshake128.owner));
        assert!(cshake128.lifecycle == CshakeLifecycle::Vacated);
        assert_eq!(
            cshake128.update(b"second"),
            Err(HardenedSha3Error::StateConsumed)
        );
        assert!(matches!(
            cshake128.finalize_xof_erasing_source(),
            Err(HardenedSha3Error::StateConsumed)
        ));

        let cshake256 = HardenedCshake256::new(b"KMAC", b"explicit wipe");
        assert!(cshake256.is_ok());
        let Ok(mut cshake256) = cshake256 else {
            return;
        };
        cshake256.wipe_in_place();
        assert!(is_cleared(&cshake256.owner));
        assert!(cshake256.lifecycle == CshakeLifecycle::Vacated);
        assert_eq!(
            cshake256.check_additional_bytes(1),
            Err(HardenedSha3Error::StateConsumed)
        );
        assert!(matches!(
            cshake256.finalize_xof_erasing_source(),
            Err(HardenedSha3Error::StateConsumed)
        ));
    }
}
