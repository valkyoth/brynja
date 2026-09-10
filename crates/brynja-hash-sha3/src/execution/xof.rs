use super::{Error, Execution, INLINE_OUTPUT_BYTES, Report, engine::State};
use crate::{Fips202BitString, Fips202Output};

macro_rules! xof {
    ($name:ident, $reader:ident, $rate:expr) => {
        /// Public-data SHAKE absorbing state, retaining one selected route.
        pub struct $name<'a> {
            state: State<$rate>,
            execution: Execution<'a>,
        }
        impl<'a> $name<'a> {
            /// Checks identity and health before creating an empty state.
            pub fn new(execution: Execution<'a>) -> Result<Self, Error> {
                execution.check()?;
                Ok(Self {
                    state: State::new(execution.route()),
                    execution,
                })
            }
            /// Successfully absorbed complete-byte count.
            #[must_use]
            pub const fn message_bytes(&self) -> u128 {
                self.state.message_bytes
            }
            /// Preflights additional complete bytes without mutation.
            pub fn check_additional_bytes(&self, count: u128) -> Result<(), Error> {
                State::<$rate>::check_bytes(self.state.message_bytes, count).map(|_| ())
            }
            /// Preflights the consuming canonical bit tail without mutation.
            pub fn check_additional_bits(&self, count: u128) -> Result<(), Error> {
                State::<$rate>::check_bits(self.state.message_bytes, count)
            }
            /// Actual successful work and immutable selection.
            #[must_use]
            pub const fn report(&self) -> Report {
                self.state.report
            }
            /// Transactional absorption; empty updates still reject lost health.
            pub fn update(&mut self, input: &[u8]) -> Result<(), Error> {
                self.state.update(&self.execution, input)
            }
            /// Consumes absorption, including padding, into one affine XOF reader.
            pub fn finalize_xof(self) -> Result<$reader<'a>, Error> {
                let bits = Fips202BitString::new(&[], 0).map_err(|_| Error::LengthOverflow)?;
                self.finalize_bits_xof(bits)
            }
            /// Consumes an LSB-first final bit tail; no later absorption is possible.
            pub fn finalize_bits_xof(
                mut self,
                input: Fips202BitString<'_>,
            ) -> Result<$reader<'a>, Error> {
                self.state.finish(&self.execution, input, 0x1f, 5)?;
                Ok($reader {
                    state: self.state,
                    execution: self.execution,
                })
            }
            /// One-shot arbitrary-sized output with caller-owned staging scratch.
            /// On failure the destination is unchanged; scratch may be modified.
            pub fn hash_with_scratch(
                execution: Execution<'a>,
                input: &[u8],
                output: &mut [u8],
                scratch: &mut [u8],
            ) -> Result<Report, Error> {
                if scratch.len() < output.len() {
                    return Err(Error::ScratchTooSmall);
                }
                let mut state = Self::new(execution)?;
                state.update(input)?;
                let mut reader = state.finalize_xof()?;
                reader.squeeze_with_scratch(output, scratch)?;
                Ok(reader.report())
            }
            /// One-shot canonical bit input/output, including empty outputs.
            pub fn hash_bits_with_scratch(
                execution: Execution<'a>,
                input: Fips202BitString<'_>,
                output: Fips202Output<'_>,
                scratch: &mut [u8],
            ) -> Result<Report, Error> {
                Self::new(execution)?
                    .finalize_bits_xof(input)?
                    .squeeze_final_bits_with_scratch(output, scratch)
            }
        }

        /// Affine ordinary SHAKE reader. No secret handling or implicit fallback.
        pub struct $reader<'a> {
            state: State<$rate>,
            execution: Execution<'a>,
        }
        impl $reader<'_> {
            /// Complete output bytes committed successfully so far.
            #[must_use]
            pub const fn output_bytes(&self) -> u128 {
                self.state.output_bytes
            }
            /// Actual successful work, never a health certificate.
            #[must_use]
            pub const fn report(&self) -> Report {
                self.state.report
            }
            /// Preflights additional output bytes without mutation.
            pub fn check_additional_bytes(&self, count: u128) -> Result<(), Error> {
                State::<$rate>::check_bytes(self.state.output_bytes, count).map(|_| ())
            }
            /// Preflights a consuming final bit-output request.
            pub fn check_additional_bits(&self, count: u128) -> Result<(), Error> {
                State::<$rate>::check_bits(self.state.output_bytes, count)
            }
            /// Transactional output up to INLINE_OUTPUT_BYTES using stack scratch.
            /// Larger requests return ScratchTooSmall without modifying output/state;
            /// use repeated calls or squeeze_with_scratch for arbitrary lengths.
            pub fn squeeze(&mut self, output: &mut [u8]) -> Result<(), Error> {
                self.squeeze_with_scratch(output, &mut [0; INLINE_OUTPUT_BYTES])
            }
            /// Arbitrary-sized transactional output; scratch must be at least output.len().
            /// All permutations run once into scratch before output/state commit.
            /// Even errors after many permutations preserve the destination and reader.
            /// Scratch is ordinary public storage and may change on failure.
            pub fn squeeze_with_scratch(
                &mut self,
                output: &mut [u8],
                scratch: &mut [u8],
            ) -> Result<(), Error> {
                self.state.squeeze(&self.execution, output, scratch, 8)
            }
            /// Consuming canonical final output with bounded stack scratch.
            pub fn squeeze_final_bits(self, output: Fips202Output<'_>) -> Result<Report, Error> {
                self.squeeze_final_bits_with_scratch(output, &mut [0; INLINE_OUTPUT_BYTES])
            }
            /// Consuming arbitrary-bit output; partial high bits are cleared.
            /// Errors leave destination unchanged. The consumed reader cannot resume.
            pub fn squeeze_final_bits_with_scratch(
                mut self,
                output: Fips202Output<'_>,
                scratch: &mut [u8],
            ) -> Result<Report, Error> {
                let (bytes, valid) = output.into_parts();
                self.state.squeeze(&self.execution, bytes, scratch, valid)?;
                Ok(self.state.report)
            }
        }
    };
}
xof!(Shake128, Shake128Reader, 168);
xof!(Shake256, Shake256Reader, 136);
