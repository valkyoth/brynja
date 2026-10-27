use super::{
    Error, Mode, Report,
    core_state::Core,
    output::{self, BorrowedStage, Stage},
};
use crate::policy::StrengthPolicy;
use crate::{
    Fips202BitString, KmacKeyPolicy, KmacSecretOutput, KmacServiceStatus, KmacTag,
    KmacVerification, policy::tag_policy,
};
use brynja_core::clear_owned_region;

macro_rules! fixed {
    ($profile:ident, $name:ident, $wide:literal) => {
        /// Affine keyed owner with explicit hardened execution selection.
        pub struct $name<'a> {
            core: Core<'a>,
        }
        impl<'a> $name<'a> {
            /// Selects a route before absorbing a full-strength key.
            pub fn new(mode: Mode<'a>, key: &[u8], customization: &[u8]) -> Result<Self, Error> {
                Self::new_bits(mode, crate::execution::bits(key)?, crate::execution::bits(customization)?)
            }
            /// Accepts canonical arbitrary-bit key and customization strings.
            pub fn new_bits(
                mode: Mode<'a>,
                key: Fips202BitString<'_>,
                customization: Fips202BitString<'_>,
            ) -> Result<Self, Error> {
                Ok(Self {
                    core: Core::new(mode, $wide, key, customization, StrengthPolicy::Production)?,
                })
            }
            conformance_api! { $profile;
            /// Exact standards conformance, including short/empty keys; non-approved.
            #[cfg(feature = "conformance-testing")]
            pub fn new_conformance(
                mode: Mode<'a>,
                key: &[u8],
                customization: &[u8],
            ) -> Result<Self, Error> {
                Self::new_bits_conformance(mode, crate::execution::bits(key)?, crate::execution::bits(customization)?)
            }
            }
            conformance_api! { $profile;
            /// Exact arbitrary-bit conformance; absent from production defaults.
            #[cfg(feature = "conformance-testing")]
            pub fn new_bits_conformance(
                mode: Mode<'a>,
                key: Fips202BitString<'_>,
                customization: Fips202BitString<'_>,
            ) -> Result<Self, Error> {
                Ok(Self {
                    core: Core::new(mode, $wide, key, customization, StrengthPolicy::Conformance)?,
                })
            }
            }
            /// Reports public route/health only; None means portable.
            pub fn report(&self) -> Option<Report> {
                self.core.report()
            }
            /// Reports the configured key-strength policy, never key bytes.
            pub fn key_policy(&self) -> KmacKeyPolicy {
                self.core.key_policy()
            }
            /// No FIPS approval is inferred from successful execution.
            pub const fn service_status(&self) -> KmacServiceStatus {
                KmacServiceStatus::NonApproved
            }
            /// Complete bytes accepted through update, excluding key/domain setup.
            pub fn message_bytes(&self) -> u128 {
                self.core.message_bytes()
            }
            /// Absorbs bytes; operational errors irreversibly clear the owner.
            pub fn update(&mut self, input: &[u8]) -> Result<(), Error> {
                self.core.update(input)
            }
            /// Consumes and clears the exact inline owner.
            pub fn cancel(mut self) {
                self.core.cancel();
            }
            /// Consumes the owner into a full-strength tag of at most 168 bytes.
            pub fn finalize_tag(mut self, output: &mut [u8]) -> Result<KmacTag<'_>, Error> {
                let mut scratch = Stage([0; 168]);
                self.tag(
                    None,
                    output,
                    output::valid(output.len()),
                    &mut scratch.0, StrengthPolicy::Production,
                )
            }
            /// Arbitrary-length transactional public tag using caller erasing scratch.
            pub fn finalize_tag_with_scratch<'out>(
                mut self,
                output: &'out mut [u8],
                scratch: &mut [u8],
            ) -> Result<KmacTag<'out>, Error> {
                self.tag(None, output, output::valid(output.len()), scratch, StrengthPolicy::Production)
            }
            /// Canonical final message/output bits with caller erasing scratch.
            pub fn finalize_tag_bits<'out>(
                mut self,
                message: Fips202BitString<'_>,
                output: &'out mut [u8],
                valid: u8,
                scratch: &mut [u8],
            ) -> Result<KmacTag<'out>, Error> {
                self.tag(Some(message), output, valid, scratch, StrengthPolicy::Production)
            }
            conformance_api! { $profile;
            /// Exact-conformance byte tag; scratch must cover the entire destination.
            #[cfg(feature = "conformance-testing")]
            pub fn finalize_tag_conformance<'out>(
                mut self,
                output: &'out mut [u8],
                scratch: &mut [u8],
            ) -> Result<KmacTag<'out>, Error> {
                self.tag(None, output, output::valid(output.len()), scratch, StrengthPolicy::Conformance)
            }
            }
            conformance_api! { $profile;
            /// Exact-conformance final message/output bits.
            #[cfg(feature = "conformance-testing")]
            pub fn finalize_tag_bits_conformance<'out>(
                mut self,
                message: Fips202BitString<'_>,
                output: &'out mut [u8],
                valid: u8,
                scratch: &mut [u8],
            ) -> Result<KmacTag<'out>, Error> {
                self.tag(Some(message), output, valid, scratch, StrengthPolicy::Conformance)
            }
            }
            /// Consuming secret result; every error clears the complete destination.
            pub fn finalize_secret(
                mut self,
                output: &mut [u8],
            ) -> Result<KmacSecretOutput<'_>, Error> {
                self.secret(None, output, output::valid(output.len()), StrengthPolicy::Production)
            }
            /// Consuming arbitrary-bit secret result with complete error clearing.
            pub fn finalize_secret_bits<'out>(
                mut self,
                message: Fips202BitString<'_>,
                bytes: &'out mut [u8],
                valid: u8,
            ) -> Result<KmacSecretOutput<'out>, Error> {
                self.secret(Some(message), bytes, valid, StrengthPolicy::Production)
            }
            conformance_api! { $profile;
            /// Exact-conformance typed-secret byte output.
            #[cfg(feature = "conformance-testing")]
            pub fn finalize_secret_conformance(
                mut self,
                output: &mut [u8],
            ) -> Result<KmacSecretOutput<'_>, Error> {
                self.secret(None, output, output::valid(output.len()), StrengthPolicy::Conformance)
            }
            }
            conformance_api! { $profile;
            /// Exact-conformance typed-secret arbitrary-bit output.
            #[cfg(feature = "conformance-testing")]
            pub fn finalize_secret_bits_conformance<'out>(
                mut self,
                message: Fips202BitString<'_>,
                bytes: &'out mut [u8],
                valid: u8,
            ) -> Result<KmacSecretOutput<'out>, Error> {
                self.secret(Some(message), bytes, valid, StrengthPolicy::Conformance)
            }
            }
            /// Constant-work verification for the public candidate length.
            /// Callers must bound that length and use verify_exact for a fixed protocol width.
            ///
            /// # Errors
            /// Reject on `Mismatch` or any other error; never retry through a weaker route.
            pub fn verify(mut self, candidate: &[u8]) -> Result<(), Error> {
                self.verification(None, crate::execution::bits(candidate)?, StrengthPolicy::Production)?.into_result()
            }
            /// Rejects a protocol tag-width mismatch before hashing output.
            pub fn verify_exact(
                mut self,
                candidate: Fips202BitString<'_>,
                expected_bits: u128,
            ) -> Result<(), Error> {
                if u128::try_from(candidate.bit_len()).map_err(|_| Error::OutputTooLong)?
                    != expected_bits
                {
                    return Err(Error::InvalidBitString);
                }
                self.verification(None, candidate, StrengthPolicy::Production)?.into_result()
            }
            /// Consuming canonical arbitrary-bit message and tag verification.
            ///
            /// # Errors
            /// Reject on `Mismatch` or any other error; never retry through a weaker route.
            pub fn verify_bits(
                mut self,
                message: Fips202BitString<'_>,
                candidate: Fips202BitString<'_>,
            ) -> Result<(), Error> {
                self.verification(Some(message), candidate, StrengthPolicy::Production)?.into_result()
            }
            conformance_api! { $profile;
            /// Exact-conformance byte verification, including weak tag parameters.
            #[cfg(feature = "conformance-testing")]
            ///
            /// # Errors
            /// Reject on `Mismatch` or any other error; never retry through a weaker route.
            pub fn verify_conformance(
                mut self,
                candidate: &[u8],
            ) -> Result<(), Error> {
                self.verification(None, crate::execution::bits(candidate)?, StrengthPolicy::Conformance)?.into_result()
            }
            }
            conformance_api! { $profile;
            /// Exact-conformance arbitrary-bit verification.
            #[cfg(feature = "conformance-testing")]
            ///
            /// # Errors
            /// Reject on `Mismatch` or any other error; never retry through a weaker route.
            pub fn verify_bits_conformance(
                mut self,
                message: Fips202BitString<'_>,
                candidate: Fips202BitString<'_>,
            ) -> Result<(), Error> {
                self.verification(Some(message), candidate, StrengthPolicy::Conformance)?.into_result()
            }
            }
            fn tag<'out>(
                &mut self,
                message: Option<Fips202BitString<'_>>,
                bytes: &'out mut [u8],
                valid: u8,
                scratch: &mut [u8],
                strength_policy: StrengthPolicy,
            ) -> Result<KmacTag<'out>, Error> {
                let stage = BorrowedStage(scratch);
                let bits = output::length_bits(bytes.len(), valid)?;
                let policy = tag_policy(bits, self.core.strength());
                self.core.finish(message, bits, false, strength_policy)?;
                self.core.public(bytes, valid, stage.0, true)?;
                Ok(KmacTag::new(bytes, bits, policy))
            }
            fn secret<'out>(
                &mut self,
                message: Option<Fips202BitString<'_>>,
                bytes: &'out mut [u8],
                valid: u8,
                strength_policy: StrengthPolicy,
            ) -> Result<KmacSecretOutput<'out>, Error> {
                let _ = clear_owned_region(bytes);
                let bits = output::length_bits(bytes.len(), valid)?;
                self.core.finish(message, bits, false, strength_policy)?;
                self.core.secret(bytes, valid, true)
            }
            fn verification(
                &mut self,
                message: Option<Fips202BitString<'_>>,
                candidate: Fips202BitString<'_>,
                strength_policy: StrengthPolicy,
            ) -> Result<KmacVerification, Error> {
                let bits = u128::try_from(candidate.bit_len()).map_err(|_| Error::OutputTooLong)?;
                self.core.finish(message, bits, false, strength_policy)?;
                output::verify(&mut self.core, candidate)
            }
        }
    };
}
fixed!(production, Kmac128, false);
fixed!(production, Kmac256, true);

#[cfg(feature = "conformance-testing")]
pub(crate) mod conformance {
    use super::*;
    fixed!(conformance, Kmac128, false);
    fixed!(conformance, Kmac256, true);
}
