use super::{Error, Execution, Output, Report};
use crate::{BitString, sha512_state::Sha512State};

macro_rules! named {
    ($name:ident, $state:ty, $new:expr, $digest:ty, $render:expr, $length:ty, $wide:expr) => {
        /// Ordinary non-erasing SHA-2 stream bound to one explicit execution route.
        /// Finalization consumes the owner. Public message lengths control work.
        pub struct $name<'a> {
            state: $state,
            execution: Execution<'a>,
            report: Report,
        }
        impl<'a> $name<'a> {
            /// Checks route identity and health before creating an empty stream.
            pub fn new(execution: Execution<'a>) -> Result<Self, Error> {
                execution.check($wide)?;
                let report = Report::new(execution.route(), 0);
                Ok(Self {
                    state: $new,
                    execution,
                    report,
                })
            }
            /// Successfully accepted complete bytes.
            #[must_use]
            pub fn message_bytes(&self) -> $length {
                self.state.message_bytes()
            }
            /// Checks public stream length metadata without changing state.
            pub fn check_additional_bytes(&self, count: $length) -> Result<(), Error> {
                self.state
                    .check_additional_bytes(count)
                    .map_err(|_| Error::MessageTooLong)
            }
            /// Checks a final bit count before mutation.
            pub fn check_additional_bits(&self, count: $length) -> Result<(), Error> {
                self.state
                    .check_additional_bits(count)
                    .map_err(|_| Error::MessageTooLong)
            }
            /// Successful work so far, not a health certificate or execution permit.
            #[must_use]
            pub const fn report(&self) -> Report {
                self.report
            }
            /// Absorbs public bytes transactionally, including empty-update health checks.
            pub fn update(&mut self, input: &[u8]) -> Result<(), Error> {
                self.state
                    .execution_update(input, &self.execution, &mut self.report)
            }
            /// Consumes the stream; padding compression uses the selected route.
            pub fn finalize(self) -> Result<Output<$digest>, Error> {
                self.finalize_bits(BitString::new(&[], 0).map_err(|_| Error::MessageTooLong)?)
            }
            /// Consumes a final canonical MSB-first bit tail; no later update is possible.
            pub fn finalize_bits(mut self, input: BitString<'_>) -> Result<Output<$digest>, Error> {
                let value =
                    self.state
                        .execution_finalize(input, &self.execution, &mut self.report)?;
                Ok(Output {
                    digest: ($render)(value),
                    report: self.report,
                })
            }
            /// One-shot complete-byte public hashing with the exact digest identity.
            pub fn hash(execution: Execution<'a>, input: &[u8]) -> Result<Output<$digest>, Error> {
                let mut state = Self::new(execution)?;
                state.update(input)?;
                state.finalize()
            }
            /// One-shot arbitrary-bit public hashing with the exact digest identity.
            pub fn hash_bits(
                execution: Execution<'a>,
                input: BitString<'_>,
            ) -> Result<Output<$digest>, Error> {
                Self::new(execution)?.finalize_bits(input)
            }
        }
    };
}

named!(
    Sha224,
    crate::Sha224,
    crate::Sha224::new(),
    crate::Sha224Digest,
    core::convert::identity,
    u64,
    false
);
named!(
    Sha256,
    crate::Sha256,
    crate::Sha256::new(),
    crate::Sha256Digest,
    core::convert::identity,
    u64,
    false
);
named!(
    Sha384,
    Sha512State,
    Sha512State::new(crate::sha384::INITIAL_STATE),
    crate::Sha384Digest,
    |words| crate::Sha384Digest::from_bytes(crate::sha512_t::leftmost_bytes(words)),
    u128,
    true
);
named!(
    Sha512,
    Sha512State,
    Sha512State::new(crate::sha512::INITIAL_STATE),
    crate::Sha512Digest,
    |words| crate::Sha512Digest::from_bytes(crate::sha512_t::leftmost_bytes(words)),
    u128,
    true
);
named!(
    Sha512_224,
    Sha512State,
    Sha512State::new(crate::sha512_t::SHA512_224_INITIAL_STATE),
    crate::Sha512_224Digest,
    |words| crate::Sha512_224Digest::from_bytes(crate::sha512_t::leftmost_bytes(words)),
    u128,
    true
);
named!(
    Sha512_256,
    Sha512State,
    Sha512State::new(crate::sha512_t::SHA512_256_INITIAL_STATE),
    crate::Sha512_256Digest,
    |words| crate::Sha512_256Digest::from_bytes(crate::sha512_t::leftmost_bytes(words)),
    u128,
    true
);
