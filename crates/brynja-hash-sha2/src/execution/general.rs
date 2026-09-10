use super::{Error, Execution, Output, Report};
use crate::{BitString, Sha512TBits, Sha512TDigest, sha512_state::Sha512State};

/// Ordinary general SHA-512/t stream. IV derivation stays portable and public.
///
/// No conversion from hardened states or secret-output owners is provided.
pub struct Sha512T<'a> {
    parameter: Sha512TBits,
    state: Sha512State,
    execution: Execution<'a>,
    report: Report,
}

impl<'a> Sha512T<'a> {
    /// Checks route/identity, derives the exact public IV, then starts a stream.
    pub fn new(parameter: Sha512TBits, execution: Execution<'a>) -> Result<Self, Error> {
        execution.check(true)?;
        let report = Report::new(execution.route(), 1);
        Ok(Self {
            parameter,
            state: Sha512State::new(parameter.initial_words()),
            execution,
            report,
        })
    }
    /// Exact general-t identity; /384 is not admitted as general-t.
    #[must_use]
    pub const fn parameter(&self) -> Sha512TBits {
        self.parameter
    }
    /// Accepted complete bytes.
    #[must_use]
    pub fn message_bytes(&self) -> u128 {
        self.state.message_bytes()
    }
    /// Checks byte-oriented metadata without mutation.
    pub fn check_additional_bytes(&self, count: u128) -> Result<(), Error> {
        self.state
            .check_additional_bytes(count)
            .map_err(|_| Error::MessageTooLong)
    }
    /// Checks additional final bits without mutation.
    pub fn check_additional_bits(&self, count: u128) -> Result<(), Error> {
        self.state
            .check_additional_bits(count)
            .map_err(|_| Error::MessageTooLong)
    }
    /// Successful message/padding work and separately accounted portable IV work.
    #[must_use]
    pub const fn report(&self) -> Report {
        self.report
    }
    /// Absorbs public bytes; rejection preserves the live state and report.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        self.state
            .execution_update(input, &self.execution, &mut self.report)
    }
    /// Consumes the stream and returns a canonical public digest, not secret material.
    pub fn finalize(self) -> Result<Output<Sha512TDigest>, Error> {
        self.finalize_bits(BitString::new(&[], 0).map_err(|_| Error::MessageTooLong)?)
    }
    /// Consumes an arbitrary-bit final tail; the low unused output bits are zero.
    pub fn finalize_bits(mut self, input: BitString<'_>) -> Result<Output<Sha512TDigest>, Error> {
        let words = self
            .state
            .execution_finalize(input, &self.execution, &mut self.report)?;
        let bytes: [u8; 64] = crate::sha512_t::leftmost_bytes(words);
        let digest = Sha512TDigest::computed(self.parameter, &bytes).map_err(Error::Digest)?;
        Ok(Output {
            digest,
            report: self.report,
        })
    }
    /// One-shot public byte hashing for any valid general-t parameter.
    pub fn hash(
        parameter: Sha512TBits,
        execution: Execution<'a>,
        input: &[u8],
    ) -> Result<Output<Sha512TDigest>, Error> {
        let mut state = Self::new(parameter, execution)?;
        state.update(input)?;
        state.finalize()
    }
    /// One-shot public arbitrary-bit hashing for any valid general-t parameter.
    pub fn hash_bits(
        parameter: Sha512TBits,
        execution: Execution<'a>,
        input: BitString<'_>,
    ) -> Result<Output<Sha512TDigest>, Error> {
        Self::new(parameter, execution)?.finalize_bits(input)
    }
}
