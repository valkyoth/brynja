use super::{Error, Execution, Output, Report, engine::State};
use crate::Fips202BitString;

macro_rules! fixed {
    ($name:ident, $digest:ident, $rate:expr, $size:expr) => {
        /// Ordinary public-data fixed hash retaining one healthy execution route.
        /// No state erasure, Clone, reset or implicit secret declassification.
        pub struct $name<'a> {
            state: State<$rate>,
            execution: Execution<'a>,
        }

        impl<'a> $name<'a> {
            /// Validates identity and health before absorbing anything.
            pub fn new(execution: Execution<'a>) -> Result<Self, Error> {
                execution.check()?;
                Ok(Self {
                    state: State::new(execution.route()),
                    execution,
                })
            }
            /// Successfully absorbed complete bytes.
            #[must_use]
            pub const fn message_bytes(&self) -> u128 {
                self.state.message_bytes
            }
            /// Checks byte length without modifying state.
            pub fn check_additional_bytes(&self, count: u128) -> Result<(), Error> {
                State::<$rate>::check_bytes(self.state.message_bytes, count).map(|_| ())
            }
            /// Checks a consuming final bit-input length without mutation.
            pub fn check_additional_bits(&self, count: u128) -> Result<(), Error> {
                State::<$rate>::check_bits(self.state.message_bytes, count)
            }
            /// Successful route and actual work; not an authority.
            #[must_use]
            pub const fn report(&self) -> Report {
                self.state.report
            }
            /// Transactionally absorbs public bytes. Empty updates check health too.
            pub fn update(&mut self, input: &[u8]) -> Result<(), Error> {
                self.state.update(&self.execution, input)
            }
            /// Consumes the stream and computes suffix/padding on its selected route.
            pub fn finalize(self) -> Result<Output<crate::$digest>, Error> {
                let bits = Fips202BitString::new(&[], 0).map_err(|_| Error::LengthOverflow)?;
                self.finalize_bits(bits)
            }
            /// Consuming canonical LSB-first tail; updates cannot follow a partial byte.
            pub fn finalize_bits(
                mut self,
                input: Fips202BitString<'_>,
            ) -> Result<Output<crate::$digest>, Error> {
                self.state.finish(&self.execution, input, 0x06, 3)?;
                Ok(Output {
                    digest: crate::$digest::from_bytes(self.state.digest::<$size>()),
                    report: self.state.report,
                })
            }
            /// Complete-byte one-shot hashing of public data.
            pub fn hash(
                execution: Execution<'a>,
                input: &[u8],
            ) -> Result<Output<crate::$digest>, Error> {
                let mut state = Self::new(execution)?;
                state.update(input)?;
                state.finalize()
            }
            /// Arbitrary-bit one-shot hashing of public data.
            pub fn hash_bits(
                execution: Execution<'a>,
                input: Fips202BitString<'_>,
            ) -> Result<Output<crate::$digest>, Error> {
                Self::new(execution)?.finalize_bits(input)
            }
        }
    };
}
fixed!(Sha3_224, Sha3_224Digest, 144, 28);
fixed!(Sha3_256, Sha3_256Digest, 136, 32);
fixed!(Sha3_384, Sha3_384Digest, 104, 48);
fixed!(Sha3_512, Sha3_512Digest, 72, 64);
