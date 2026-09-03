use brynja_hash_sha3::{
    Fips202BitString, Fips202Output, HardenedCshake128, HardenedCshake128Reader, HardenedCshake256,
    HardenedCshake256Reader,
};

use crate::{
    backend::CshakeReader,
    core_state::KmacCore,
    error::KmacError,
    output::{KmacPublicDeclassification, KmacSecretOutput},
    policy::{KmacKeyPolicy, KmacServiceStatus},
};

macro_rules! xof_reader {
    ($reader:ident, $backend:ty, $label:literal) => {
        #[doc = concat!("Secret-bearing incremental ", $label, " reader.")]
        pub struct $reader {
            inner: $backend,
        }

        impl $reader {
            /// Writes one explicitly declassified public fragment.
            pub fn squeeze_public(
                &mut self,
                output: &mut [u8],
                _authority: KmacPublicDeclassification,
            ) -> Result<(), KmacError> {
                CshakeReader::squeeze_public(&mut self.inner, output).map_err(KmacError::from)
            }

            /// Writes one fragment and transfers typed secret ownership.
            pub fn squeeze_secret<'output>(
                &mut self,
                output: &'output mut [u8],
            ) -> Result<KmacSecretOutput<'output>, KmacError> {
                CshakeReader::squeeze_secret(&mut self.inner, output)
                    .map(KmacSecretOutput::new)
                    .map_err(KmacError::from)
            }

            /// Consumes the reader after one final arbitrary-bit public fragment.
            pub fn squeeze_final_bits_public(
                self,
                output: Fips202Output<'_>,
                _authority: KmacPublicDeclassification,
            ) -> Result<(), KmacError> {
                CshakeReader::squeeze_final_bits_public(self.inner, output).map_err(KmacError::from)
            }

            /// Consumes the reader after one final arbitrary-bit secret fragment.
            pub fn squeeze_final_bits_secret<'output>(
                self,
                output: Fips202Output<'output>,
            ) -> Result<KmacSecretOutput<'output>, KmacError> {
                CshakeReader::squeeze_final_bits_secret(self.inner, output)
                    .map(KmacSecretOutput::new)
                    .map_err(KmacError::from)
            }

            /// Reports the current non-approved service status.
            #[must_use]
            pub const fn service_status(&self) -> KmacServiceStatus {
                KmacServiceStatus::NonApproved
            }

            /// Returns the complete output byte count emitted so far.
            #[must_use]
            pub fn output_bytes(&self) -> u128 {
                CshakeReader::output_bytes(&self.inner)
            }

            /// Checks an additional output byte count without mutation.
            pub fn check_additional_bytes(&self, additional: u128) -> Result<(), KmacError> {
                CshakeReader::check_additional_bytes(&self.inner, additional)
                    .map_err(KmacError::from)
            }

            /// Checks an additional output bit count without mutation.
            pub fn check_additional_bits(&self, additional: u128) -> Result<(), KmacError> {
                CshakeReader::check_additional_bits(&self.inner, additional)
                    .map_err(KmacError::from)
            }

            /// Consumes and clears the reader without further output.
            pub fn cancel(self) {}
        }
    };
}

xof_reader!(KmacXof128Reader, HardenedCshake128Reader, "KMACXOF128");
xof_reader!(KmacXof256Reader, HardenedCshake256Reader, "KMACXOF256");

macro_rules! xof_state {
    ($state:ident, $reader:ident, $backend:ty, $rate:literal, $strength:literal, $label:literal) => {
        #[doc = concat!("Secret-bearing streaming ", $label, " state.")]
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
            #[cfg(feature = "conformance-testing")]
            pub fn new_conformance(key: &[u8], customization: &[u8]) -> Result<Self, KmacError> {
                let key = byte_string(key)?;
                let customization = byte_string(customization)?;
                Self::new_bits_conformance(key, customization)
            }

            /// Creates an exact-conformance arbitrary-bit state.
            #[cfg(feature = "conformance-testing")]
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

            /// Finalizes a full-strength production state into an incremental reader.
            pub fn finalize_xof(mut self) -> Result<$reader, KmacError> {
                self.core
                    .finish_xof(None, true)
                    .map(|inner| $reader { inner })
            }

            /// Finalizes an exact-conformance state into an incremental reader.
            #[cfg(feature = "conformance-testing")]
            pub fn finalize_xof_conformance(mut self) -> Result<$reader, KmacError> {
                self.core
                    .finish_xof(None, false)
                    .map(|inner| $reader { inner })
            }

            /// Finalizes after one canonical arbitrary-bit message.
            pub fn finalize_bits_xof(
                mut self,
                final_message: Fips202BitString<'_>,
            ) -> Result<$reader, KmacError> {
                self.core
                    .finish_xof(Some(final_message), true)
                    .map(|inner| $reader { inner })
            }

            /// Finalizes exact conformance after an arbitrary-bit message.
            #[cfg(feature = "conformance-testing")]
            pub fn finalize_bits_xof_conformance(
                mut self,
                final_message: Fips202BitString<'_>,
            ) -> Result<$reader, KmacError> {
                self.core
                    .finish_xof(Some(final_message), false)
                    .map(|inner| $reader { inner })
            }

            /// Consumes and clears this state without producing output.
            pub fn cancel(self) {}
        }
    };
}

xof_state!(
    KmacXof128,
    KmacXof128Reader,
    HardenedCshake128,
    168,
    128,
    "KMACXOF128"
);
xof_state!(
    KmacXof256,
    KmacXof256Reader,
    HardenedCshake256,
    136,
    256,
    "KMACXOF256"
);

fn byte_string(input: &[u8]) -> Result<Fips202BitString<'_>, KmacError> {
    let valid = if input.is_empty() { 0 } else { 8 };
    Fips202BitString::new(input, valid).map_err(|_| KmacError::InvalidBitString)
}
