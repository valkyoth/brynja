use brynja_hash_core::{ExtendableOutput, Update, XofReader};

use crate::{
    Cshake128Error, Cshake256Error, Fips202BitString, Fips202Output,
    sp800185::absorb_cshake_prefix,
    sponge::{Sponge, Squeezer},
};

const CSHAKE_SUFFIX: u8 = 0x04;
const CSHAKE_SUFFIX_BITS: u8 = 3;

macro_rules! cshake {
    ($state:ident, $reader:ident, $error:ident, $rate:literal, $label:literal) => {
        #[doc = concat!("Portable streaming ", $label, " absorbing state.")]
        ///
        /// The function name and customization are absorbed once during
        /// construction. Finalization consumes this state, so absorption after
        /// squeezing is structurally impossible. This ordinary state does not
        /// erase absorbed data; use the hardened variant when input or derived
        /// state is secret-bearing.
        pub struct $state {
            sponge: Sponge<$rate>,
            customized: bool,
            setup_bytes: u128,
        }

        impl $state {
            /// Upper bound of the underlying input counter.
            ///
            /// A customized instance consumes at least one rate block for its
            /// encoded function-name and customization prefix, so its remaining
            /// message capacity is smaller than this absolute bound.
            pub const MAX_MESSAGE_BYTES: u128 = Sponge::<$rate>::MAX_MESSAGE_BYTES;

            /// Creates a byte-oriented state with `N = function_name` and
            /// `S = customization`.
            pub fn new(function_name: &[u8], customization: &[u8]) -> Result<Self, $error> {
                let function_name =
                    byte_string(function_name).map_err(|()| $error::MessageTooLong)?;
                let customization =
                    byte_string(customization).map_err(|()| $error::MessageTooLong)?;
                Self::new_bits(function_name, customization)
            }

            /// Creates a state over canonical arbitrary-bit `N` and `S`.
            pub fn new_bits(
                function_name: Fips202BitString<'_>,
                customization: Fips202BitString<'_>,
            ) -> Result<Self, $error> {
                let mut sponge = Sponge::<$rate>::new();
                let customized =
                    absorb_cshake_prefix($rate, function_name, customization, |bytes| {
                        sponge.update(bytes)
                    })
                    .map_err(|()| $error::MessageTooLong)?;
                let setup_bytes = sponge.message_bytes();
                Ok(Self {
                    sponge,
                    customized,
                    setup_bytes,
                })
            }

            /// Returns the complete message-byte count accepted after setup.
            ///
            /// Domain-separation setup bytes are intentionally excluded.
            #[must_use]
            pub const fn message_bytes(&self) -> u128 {
                self.sponge.message_bytes().saturating_sub(self.setup_bytes)
            }

            /// Checks an additional message byte count without mutation.
            pub fn check_additional_bytes(&self, additional: u128) -> Result<(), $error> {
                self.sponge
                    .check_additional_bytes(additional)
                    .map_err(|()| $error::MessageTooLong)
            }

            /// Checks an additional exact message bit count without mutation.
            pub fn check_additional_bits(&self, additional: u128) -> Result<(), $error> {
                self.sponge
                    .check_additional_bits(additional)
                    .map_err(|()| $error::MessageTooLong)
            }

            /// Absorbs every byte or rejects before observable mutation.
            pub fn update(&mut self, input: &[u8]) -> Result<(), $error> {
                self.sponge
                    .update(input)
                    .map_err(|()| $error::MessageTooLong)
            }

            /// Consumes absorption and returns an incremental output reader.
            #[must_use]
            pub fn finalize_xof(self) -> $reader {
                $reader(self.finish(None))
            }

            /// Consumes absorption after one final canonical bit string.
            pub fn finalize_bits_xof(
                mut self,
                input: Fips202BitString<'_>,
            ) -> Result<$reader, $error> {
                let bits = u128::try_from(input.bit_len()).map_err(|_| $error::MessageTooLong)?;
                self.check_additional_bits(bits)?;
                let (complete, partial) = input.split();
                self.update(complete)?;
                Ok($reader(self.finish(partial)))
            }

            /// Consumes the state and fills one fixed caller destination.
            pub fn finalize_into(self, output: &mut [u8]) -> Result<(), $error> {
                self.finalize_xof().squeeze(output)
            }

            fn finish(self, partial: Option<(u8, u8)>) -> Squeezer<$rate> {
                if self.customized {
                    self.sponge
                        .finalize_domain_xof(partial, CSHAKE_SUFFIX, CSHAKE_SUFFIX_BITS)
                } else {
                    self.sponge
                        .finalize_domain_xof(partial, crate::sponge::SHAKE_SUFFIX, 5)
                }
            }
        }

        impl Update for $state {
            type Error = $error;

            fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
                Self::update(self, input)
            }
        }

        impl ExtendableOutput for $state {
            type Reader = $reader;

            fn finalize_xof(self) -> Self::Reader {
                Self::finalize_xof(self)
            }
        }

        #[doc = concat!("Incremental ", $label, " output reader.")]
        pub struct $reader(Squeezer<$rate>);

        impl $reader {
            /// Maximum output byte count representable by this reader.
            pub const MAX_OUTPUT_BYTES: u128 = Squeezer::<$rate>::MAX_OUTPUT_BYTES;

            /// Returns the complete-byte output count already emitted.
            #[must_use]
            pub const fn output_bytes(&self) -> u128 {
                self.0.output_bytes()
            }

            /// Checks an additional byte count without mutation.
            pub fn check_additional_bytes(&self, additional: u128) -> Result<(), $error> {
                self.0
                    .check_additional_bytes(additional)
                    .map_err(|()| $error::OutputTooLong)
            }

            /// Checks an additional bit count without mutation.
            pub fn check_additional_bits(&self, additional: u128) -> Result<(), $error> {
                self.0
                    .check_additional_bits(additional)
                    .map_err(|()| $error::OutputTooLong)
            }

            /// Fills a complete caller destination or rejects before mutation.
            pub fn squeeze(&mut self, output: &mut [u8]) -> Result<(), $error> {
                self.0.squeeze(output).map_err(|()| $error::OutputTooLong)
            }

            /// Consumes the reader after a final arbitrary-bit output.
            pub fn squeeze_final_bits(self, output: Fips202Output<'_>) -> Result<(), $error> {
                self.0
                    .squeeze_final_bits(output)
                    .map_err(|()| $error::OutputTooLong)
            }
        }

        impl XofReader for $reader {
            type Error = $error;

            fn squeeze(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
                Self::squeeze(self, output)
            }
        }
    };
}

cshake!(Cshake128, Cshake128Reader, Cshake128Error, 168, "cSHAKE128");
cshake!(Cshake256, Cshake256Reader, Cshake256Error, 136, "cSHAKE256");

/// Computes byte-oriented cSHAKE128 into one fixed destination.
pub fn cshake128(
    input: &[u8],
    function_name: &[u8],
    customization: &[u8],
    output: &mut [u8],
) -> Result<(), Cshake128Error> {
    let mut state = Cshake128::new(function_name, customization)?;
    state.update(input)?;
    state.finalize_into(output)
}

/// Computes byte-oriented cSHAKE256 into one fixed destination.
pub fn cshake256(
    input: &[u8],
    function_name: &[u8],
    customization: &[u8],
    output: &mut [u8],
) -> Result<(), Cshake256Error> {
    let mut state = Cshake256::new(function_name, customization)?;
    state.update(input)?;
    state.finalize_into(output)
}

/// Computes arbitrary-bit cSHAKE128 into an arbitrary-bit destination.
pub fn cshake128_bits(
    input: Fips202BitString<'_>,
    function_name: Fips202BitString<'_>,
    customization: Fips202BitString<'_>,
    output: Fips202Output<'_>,
) -> Result<(), Cshake128Error> {
    Cshake128::new_bits(function_name, customization)?
        .finalize_bits_xof(input)?
        .squeeze_final_bits(output)
}

/// Computes arbitrary-bit cSHAKE256 into an arbitrary-bit destination.
pub fn cshake256_bits(
    input: Fips202BitString<'_>,
    function_name: Fips202BitString<'_>,
    customization: Fips202BitString<'_>,
    output: Fips202Output<'_>,
) -> Result<(), Cshake256Error> {
    Cshake256::new_bits(function_name, customization)?
        .finalize_bits_xof(input)?
        .squeeze_final_bits(output)
}

fn byte_string(input: &[u8]) -> Result<Fips202BitString<'_>, ()> {
    let valid = if input.is_empty() { 0 } else { 8 };
    Fips202BitString::new(input, valid).map_err(|_| ())
}
