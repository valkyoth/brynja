mod compress32;
mod compress64;
mod output;
mod owner;
mod state32;
mod state64;

use brynja_core::OwnedSecretRegion;

use crate::{BitString, sha224, sha256, sha384, sha512, sha512_t};

pub use output::{HardenedSha2Error, PublicDeclassification};
use output::{clear_failed_secret_output, write_public, write_secret};
use owner::HardenedSha2Owner;

mod sealed {
    pub trait Registered {}
}

/// Sealed capability implemented only by Brynja's hardened SHA-2 states.
///
/// Downstream crates cannot implement this marker for an ordinary or
/// non-erasing wrapper.
///
/// ```compile_fail
/// use brynja_hash_sha2::HardenedSha2State;
/// struct Forged;
/// impl HardenedSha2State for Forged {}
/// ```
///
/// ```compile_fail
/// let state = brynja_hash_sha2::HardenedSha256::new();
/// let _copy = state.clone();
/// ```
///
/// ```compile_fail
/// let state = brynja_hash_sha2::HardenedSha256::new();
/// println!("{state:?}");
/// ```
///
/// ```compile_fail
/// let mut state = brynja_hash_sha2::HardenedSha256::new();
/// state.reset();
/// ```
///
/// ```compile_fail
/// let hardened = brynja_hash_sha2::HardenedSha256::new();
/// let _ordinary = brynja_hash_sha2::Sha256::from(hardened);
/// ```
pub trait HardenedSha2State: sealed::Registered {}

macro_rules! hardened32 {
    ($name:ident, $initial:expr, $output:expr, $label:literal) => {
        #[doc = concat!("Portable secret-bearing ", $label, " streaming state.")]
        ///
        /// This affine type is neither cloneable, copyable, formattable nor
        /// resettable. It owns and clears every source-declared internal byte
        /// region. Finalization requires either explicit public declassification
        /// or a caller-owned secret destination.
        pub struct $name {
            owner: HardenedSha2Owner,
        }

        impl $name {
            /// Maximum arbitrary-bit message length.
            pub const MAX_MESSAGE_BITS: u64 = u64::MAX;
            /// Maximum byte-oriented message length.
            pub const MAX_MESSAGE_BYTES: u64 = u64::MAX / 8;

            #[doc = concat!("Creates an empty hardened ", $label, " state.")]
            #[must_use]
            pub fn new() -> Self {
                Self {
                    owner: HardenedSha2Owner::new32($initial),
                }
            }

            /// Returns the number of accepted complete message bytes.
            #[must_use]
            pub fn message_bytes(&self) -> u64 {
                self.owner.message_bytes32()
            }

            /// Checks a byte count without mutating this state.
            pub fn check_additional_bytes(&self, additional: u64) -> Result<(), HardenedSha2Error> {
                self.owner
                    .check_bytes32(additional)
                    .map_err(|_| HardenedSha2Error::MessageTooLong)
            }

            /// Checks a bit count without mutating this state.
            pub fn check_additional_bits(&self, additional: u64) -> Result<(), HardenedSha2Error> {
                self.owner
                    .check_bits32(additional)
                    .map_err(|_| HardenedSha2Error::MessageTooLong)
            }

            /// Absorbs the complete byte slice or rejects it without mutation.
            pub fn update(&mut self, input: &[u8]) -> Result<(), HardenedSha2Error> {
                self.owner
                    .update32(input)
                    .map_err(|_| HardenedSha2Error::MessageTooLong)
            }

            /// Consumes the state and writes an explicitly public digest.
            pub fn finalize_public(
                mut self,
                destination: &mut [u8],
                authority: PublicDeclassification,
            ) -> Result<(), HardenedSha2Error> {
                if destination.len() != $output {
                    return Err(HardenedSha2Error::OutputLength);
                }
                let bits = self.owner.message_bytes32().wrapping_mul(8);
                self.owner.finalize32(None, bits, $output);
                let output = self
                    .owner
                    .staged($output)
                    .ok_or(HardenedSha2Error::OutputLength)?;
                write_public(output, destination, authority)
            }

            /// Consumes the state and transfers a typed secret digest owner.
            pub fn finalize_secret<'output>(
                mut self,
                destination: &'output mut [u8],
            ) -> Result<OwnedSecretRegion<'output>, HardenedSha2Error> {
                let bits = self.owner.message_bytes32().wrapping_mul(8);
                self.owner.finalize32(None, bits, $output);
                let output = match self.owner.staged($output) {
                    Some(output) => output,
                    None => {
                        return Err(clear_failed_secret_output(
                            destination,
                            HardenedSha2Error::OutputLength,
                        ));
                    }
                };
                write_secret(output, destination)
            }

            /// Consumes the state with one final canonical bit string and
            /// writes an explicitly public digest.
            pub fn finalize_bits_public(
                mut self,
                input: BitString<'_>,
                destination: &mut [u8],
                authority: PublicDeclassification,
            ) -> Result<(), HardenedSha2Error> {
                if destination.len() != $output {
                    return Err(HardenedSha2Error::OutputLength);
                }
                let bits = state32::finalize_bits_length32(&self.owner, input)
                    .map_err(|_| HardenedSha2Error::MessageTooLong)?;
                let (complete, partial) = input.split();
                self.update(complete)?;
                self.owner.finalize32(partial, bits, $output);
                let output = self
                    .owner
                    .staged($output)
                    .ok_or(HardenedSha2Error::OutputLength)?;
                write_public(output, destination, authority)
            }

            /// Consumes the state with one final canonical bit string and
            /// transfers a typed secret digest owner.
            pub fn finalize_bits_secret<'output>(
                mut self,
                input: BitString<'_>,
                destination: &'output mut [u8],
            ) -> Result<OwnedSecretRegion<'output>, HardenedSha2Error> {
                let bits = match state32::finalize_bits_length32(&self.owner, input) {
                    Ok(bits) => bits,
                    Err(()) => {
                        return Err(clear_failed_secret_output(
                            destination,
                            HardenedSha2Error::MessageTooLong,
                        ));
                    }
                };
                let (complete, partial) = input.split();
                if self.update(complete).is_err() {
                    return Err(clear_failed_secret_output(
                        destination,
                        HardenedSha2Error::MessageTooLong,
                    ));
                }
                self.owner.finalize32(partial, bits, $output);
                let output = match self.owner.staged($output) {
                    Some(output) => output,
                    None => {
                        return Err(clear_failed_secret_output(
                            destination,
                            HardenedSha2Error::OutputLength,
                        ));
                    }
                };
                write_secret(output, destination)
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl sealed::Registered for $name {}
        impl HardenedSha2State for $name {}
    };
}

macro_rules! hardened64 {
    ($name:ident, $initial:expr, $output:expr, $label:literal) => {
        #[doc = concat!("Portable secret-bearing ", $label, " streaming state.")]
        ///
        /// This affine type owns and compiler-resistantly clears all
        /// source-declared state and scratch regions on success, failure,
        /// recoverable unwind and `Drop`.
        pub struct $name {
            owner: HardenedSha2Owner,
        }

        impl $name {
            /// Maximum arbitrary-bit message length.
            pub const MAX_MESSAGE_BITS: u128 = u128::MAX;
            /// Maximum byte-oriented message length.
            pub const MAX_MESSAGE_BYTES: u128 = u128::MAX / 8;

            #[doc = concat!("Creates an empty hardened ", $label, " state.")]
            #[must_use]
            pub fn new() -> Self {
                Self {
                    owner: HardenedSha2Owner::new64($initial),
                }
            }

            /// Returns the number of accepted complete message bytes.
            #[must_use]
            pub fn message_bytes(&self) -> u128 {
                self.owner.message_bytes64()
            }

            /// Checks a byte count without mutating this state.
            pub fn check_additional_bytes(
                &self,
                additional: u128,
            ) -> Result<(), HardenedSha2Error> {
                self.owner
                    .check_bytes64(additional)
                    .map_err(|_| HardenedSha2Error::MessageTooLong)
            }

            /// Checks a bit count without mutating this state.
            pub fn check_additional_bits(&self, additional: u128) -> Result<(), HardenedSha2Error> {
                self.owner
                    .check_bits64(additional)
                    .map_err(|_| HardenedSha2Error::MessageTooLong)
            }

            /// Absorbs the complete byte slice or rejects it without mutation.
            pub fn update(&mut self, input: &[u8]) -> Result<(), HardenedSha2Error> {
                self.owner
                    .update64(input)
                    .map_err(|_| HardenedSha2Error::MessageTooLong)
            }

            /// Consumes the state and writes an explicitly public digest.
            pub fn finalize_public(
                mut self,
                destination: &mut [u8],
                authority: PublicDeclassification,
            ) -> Result<(), HardenedSha2Error> {
                if destination.len() != $output {
                    return Err(HardenedSha2Error::OutputLength);
                }
                let bits = self.owner.message_bytes64().wrapping_mul(8);
                self.owner.finalize64(None, bits, $output);
                let output = self
                    .owner
                    .staged($output)
                    .ok_or(HardenedSha2Error::OutputLength)?;
                write_public(output, destination, authority)
            }

            /// Consumes the state and transfers a typed secret digest owner.
            pub fn finalize_secret<'output>(
                mut self,
                destination: &'output mut [u8],
            ) -> Result<OwnedSecretRegion<'output>, HardenedSha2Error> {
                let bits = self.owner.message_bytes64().wrapping_mul(8);
                self.owner.finalize64(None, bits, $output);
                let output = match self.owner.staged($output) {
                    Some(output) => output,
                    None => {
                        return Err(clear_failed_secret_output(
                            destination,
                            HardenedSha2Error::OutputLength,
                        ));
                    }
                };
                write_secret(output, destination)
            }

            /// Consumes the state with one final canonical bit string and
            /// writes an explicitly public digest.
            pub fn finalize_bits_public(
                mut self,
                input: BitString<'_>,
                destination: &mut [u8],
                authority: PublicDeclassification,
            ) -> Result<(), HardenedSha2Error> {
                if destination.len() != $output {
                    return Err(HardenedSha2Error::OutputLength);
                }
                let bits = state64::finalize_bits_length64(&self.owner, input)
                    .map_err(|_| HardenedSha2Error::MessageTooLong)?;
                let (complete, partial) = input.split();
                self.update(complete)?;
                self.owner.finalize64(partial, bits, $output);
                let output = self
                    .owner
                    .staged($output)
                    .ok_or(HardenedSha2Error::OutputLength)?;
                write_public(output, destination, authority)
            }

            /// Consumes the state with one final canonical bit string and
            /// transfers a typed secret digest owner.
            pub fn finalize_bits_secret<'output>(
                mut self,
                input: BitString<'_>,
                destination: &'output mut [u8],
            ) -> Result<OwnedSecretRegion<'output>, HardenedSha2Error> {
                let bits = match state64::finalize_bits_length64(&self.owner, input) {
                    Ok(bits) => bits,
                    Err(()) => {
                        return Err(clear_failed_secret_output(
                            destination,
                            HardenedSha2Error::MessageTooLong,
                        ));
                    }
                };
                let (complete, partial) = input.split();
                if self.update(complete).is_err() {
                    return Err(clear_failed_secret_output(
                        destination,
                        HardenedSha2Error::MessageTooLong,
                    ));
                }
                self.owner.finalize64(partial, bits, $output);
                let output = match self.owner.staged($output) {
                    Some(output) => output,
                    None => {
                        return Err(clear_failed_secret_output(
                            destination,
                            HardenedSha2Error::OutputLength,
                        ));
                    }
                };
                write_secret(output, destination)
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl sealed::Registered for $name {}
        impl HardenedSha2State for $name {}
    };
}

hardened32!(HardenedSha224, sha224::INITIAL_STATE, 28, "SHA-224");
hardened32!(HardenedSha256, sha256::INITIAL_STATE, 32, "SHA-256");
hardened64!(HardenedSha384, sha384::INITIAL_STATE, 48, "SHA-384");
hardened64!(HardenedSha512, sha512::INITIAL_STATE, 64, "SHA-512");
hardened64!(
    HardenedSha512_224,
    sha512_t::SHA512_224_INITIAL_STATE,
    28,
    "SHA-512/224"
);
hardened64!(
    HardenedSha512_256,
    sha512_t::SHA512_256_INITIAL_STATE,
    32,
    "SHA-512/256"
);
