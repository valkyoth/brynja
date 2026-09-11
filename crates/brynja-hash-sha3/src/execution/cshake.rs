use super::{Error, Execution, Public, PublicBits, Report, engine::State};
use crate::{Fips202BitString, Fips202Output, sp800185::absorb_cshake_prefix};

fn bits(input: Public<'_>) -> Result<PublicBits<'_>, Error> {
    Fips202BitString::new(input.0, if input.0.is_empty() { 0 } else { 8 })
        .map(PublicBits::new)
        .map_err(|_| Error::LengthOverflow)
}

// The shared encoder's unit error includes invariant/rate failures, not just
// arithmetic overflow. Preserve a captured execution error verbatim; otherwise
// report encoding failure without guessing its cause.
fn prefix_error(backend_error: Option<Error>) -> Error {
    backend_error.unwrap_or(Error::PrefixEncoding)
}

macro_rules! cshake {
    ($name:ident, $reader:ident, $inner:ident, $rate:literal) => {
        /// Non-erasing public-data cSHAKE state on one retained execution route.
        /// N, S and message must all be public. This is not a KMAC or KDF owner.
        pub struct $name<'a> {
            state: State<$rate>,
            execution: Execution<'a>,
            customized: bool,
            setup_bytes: u128,
        }
        impl<'a> $name<'a> {
            /// Absorbs byte-oriented N/S once. Empty N/S selects SHAKE semantics.
            /// Required-kernel or prefix failures return no partially initialized owner.
            pub fn new(
                execution: Execution<'a>,
                function_name: Public<'_>,
                customization: Public<'_>,
            ) -> Result<Self, Error> {
                Self::new_bits(execution, bits(function_name)?, bits(customization)?)
            }
            /// Absorbs canonical LSB-first N/S, including non-byte-aligned strings.
            /// Every bytepad permutation uses the selected route, never a scalar detour.
            pub fn new_bits(
                execution: Execution<'a>,
                function_name: PublicBits<'_>,
                customization: PublicBits<'_>,
            ) -> Result<Self, Error> {
                execution.check()?;
                let mut state = State::<$rate>::new(execution.route());
                let mut backend_error = None;
                let customized =
                    absorb_cshake_prefix($rate, function_name.0, customization.0, |bytes| {
                        state.update(&execution, bytes).map_err(|error| {
                            backend_error = Some(error);
                        })
                    })
                    .map_err(|()| prefix_error(backend_error))?;
                let setup_bytes = state.message_bytes;
                Ok(Self {
                    state,
                    execution,
                    customized,
                    setup_bytes,
                })
            }
            /// Complete encoded setup bytes, excluded from message_bytes.
            #[must_use]
            pub const fn setup_bytes(&self) -> u128 {
                self.setup_bytes
            }
            /// Whether a nonempty N or S selected the cSHAKE domain.
            #[must_use]
            pub const fn is_customized(&self) -> bool {
                self.customized
            }
            /// Successfully absorbed complete message bytes after setup.
            #[must_use]
            pub const fn message_bytes(&self) -> u128 {
                self.state.message_bytes.saturating_sub(self.setup_bytes)
            }
            /// Actual work including setup permutations and immutable route identity.
            #[must_use]
            pub const fn report(&self) -> Report {
                self.state.report
            }
            /// Preflights bytes including already-consumed setup capacity.
            pub fn check_additional_bytes(&self, count: u128) -> Result<(), Error> {
                State::<$rate>::check_bytes(self.state.message_bytes, count).map(|_| ())
            }
            /// Preflights a consuming bit tail, including its backing byte.
            pub fn check_additional_bits(&self, count: u128) -> Result<(), Error> {
                State::<$rate>::check_bits(self.state.message_bytes, count)
            }
            /// Transactional message absorption; errors preserve the retained state.
            pub fn update(&mut self, input: Public<'_>) -> Result<(), Error> {
                self.state.update(&self.execution, input.0)
            }
            /// Consumes absorption into a cSHAKE reader, including on error.
            pub fn finalize_xof(self) -> Result<$reader<'a>, Error> {
                self.finalize_bits_xof(bits(Public::new(&[]))?)
            }
            /// Consumes a canonical LSB-first message tail and the selected domain padding.
            pub fn finalize_bits_xof(
                mut self,
                input: PublicBits<'_>,
            ) -> Result<$reader<'a>, Error> {
                let (suffix, width) = if self.customized {
                    (0x04, 3)
                } else {
                    (0x1f, 5)
                };
                self.state.finish(&self.execution, input.0, suffix, width)?;
                Ok($reader(super::$inner::from_state(
                    self.state,
                    self.execution,
                )))
            }
            /// One-shot byte input/output with arbitrary-sized caller-owned staging.
            /// Destination is unchanged on all errors; scratch may change.
            pub fn hash_with_scratch(
                execution: Execution<'a>,
                input: Public<'_>,
                function_name: Public<'_>,
                customization: Public<'_>,
                output: &mut [u8],
                scratch: &mut [u8],
            ) -> Result<Report, Error> {
                if scratch.len() < output.len() {
                    return Err(Error::ScratchTooSmall);
                }
                let mut state = Self::new(execution, function_name, customization)?;
                state.update(input)?;
                let mut reader = state.finalize_xof()?;
                reader.squeeze_with_scratch(output, scratch)?;
                Ok(reader.report())
            }
            /// One-shot arbitrary-bit X/N/S and canonical arbitrary-bit output.
            /// Destination is unchanged on error; no secret classification is inferred.
            pub fn hash_bits_with_scratch(
                execution: Execution<'a>,
                input: PublicBits<'_>,
                function_name: PublicBits<'_>,
                customization: PublicBits<'_>,
                output: Fips202Output<'_>,
                scratch: &mut [u8],
            ) -> Result<Report, Error> {
                Self::new_bits(execution, function_name, customization)?
                    .finalize_bits_xof(input)?
                    .squeeze_final_bits_with_scratch(output, scratch)
            }
        }
        /// Affine, non-erasing cSHAKE XOF reader; no public SHAKE conversion.
        pub struct $reader<'a>(super::$inner<'a>);
        impl $reader<'_> {
            /// Complete bytes successfully emitted so far.
            #[must_use]
            pub const fn output_bytes(&self) -> u128 {
                self.0.output_bytes()
            }
            /// Selected route and actual successful work, including cSHAKE setup.
            #[must_use]
            pub const fn report(&self) -> Report {
                self.0.report()
            }
            /// Preflights complete output bytes without mutation.
            pub fn check_additional_bytes(&self, count: u128) -> Result<(), Error> {
                self.0.check_additional_bytes(count)
            }
            /// Preflights a consuming bit-output request without mutation.
            pub fn check_additional_bits(&self, count: u128) -> Result<(), Error> {
                self.0.check_additional_bits(count)
            }
            /// Transactional output of at most INLINE_OUTPUT_BYTES per call.
            pub fn squeeze(&mut self, output: &mut [u8]) -> Result<(), Error> {
                self.0.squeeze(output)
            }
            /// Arbitrary-sized transactional output; scratch must cover the output.
            pub fn squeeze_with_scratch(
                &mut self,
                output: &mut [u8],
                scratch: &mut [u8],
            ) -> Result<(), Error> {
                self.0.squeeze_with_scratch(output, scratch)
            }
            /// Consuming canonical bit output with bounded inline scratch.
            pub fn squeeze_final_bits(self, output: Fips202Output<'_>) -> Result<Report, Error> {
                self.0.squeeze_final_bits(output)
            }
            /// Consuming canonical bit output; all errors preserve the destination.
            pub fn squeeze_final_bits_with_scratch(
                self,
                output: Fips202Output<'_>,
                scratch: &mut [u8],
            ) -> Result<Report, Error> {
                self.0.squeeze_final_bits_with_scratch(output, scratch)
            }
        }
    };
}
cshake!(Cshake128, Cshake128Reader, Shake128Reader, 168);
cshake!(Cshake256, Cshake256Reader, Shake256Reader, 136);

#[cfg(test)]
mod tests;
