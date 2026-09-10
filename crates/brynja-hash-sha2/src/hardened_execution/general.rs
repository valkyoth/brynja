use super::{Error, Execution, PublicDeclassification, Report, begin, engine::Engine};
use crate::{
    BitString, Sha512TBits, Sha512TDigest, Sha512TSecretDigest, hardened::HardenedSha2Owner,
};
use brynja_core::SecretRegionInitialization;

/// Complete affine general SHA-512/t stream. Public t is validated separately;
/// secret output retains its exact parameter and never uses public byte import.
pub struct Sha512T<'a> {
    parameter: Sha512TBits,
    engine: Engine<'a>,
}

impl<'a> Sha512T<'a> {
    /// Maximum complete-byte message domain.
    pub const MAX_MESSAGE_BYTES: u128 = u128::MAX / 8;
    /// Maximum arbitrary-bit message domain.
    pub const MAX_MESSAGE_BITS: u128 = u128::MAX;
    /// Derives the public IV portably, then binds the exact wide execution route.
    pub fn new(parameter: Sha512TBits, execution: Execution<'a>) -> Result<Self, Error> {
        Ok(Self {
            parameter,
            engine: Engine::new(
                HardenedSha2Owner::new64(parameter.initial_words()),
                execution,
                true,
                true,
            )?,
        })
    }
    /// Public algorithm identity, not secret input data.
    #[must_use]
    pub const fn parameter(&self) -> Sha512TBits {
        self.parameter
    }
    /// Complete bytes accepted successfully.
    #[must_use]
    pub fn message_bytes(&self) -> u128 {
        self.engine.bytes()
    }
    /// Preflight without mutation.
    pub fn check_additional_bytes(&self, count: u128) -> Result<(), Error> {
        self.engine.check_bytes(count)
    }
    /// Preflight a final arbitrary-bit count.
    pub fn check_additional_bits(&self, count: u128) -> Result<(), Error> {
        self.engine.check_bits(count).map(|_| ())
    }
    /// Public successful-work observation, not authority.
    #[must_use]
    pub const fn report(&self) -> Report {
        self.engine.report
    }
    /// Length failure preserves state; backend failure clears and fails it.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        self.engine.update(input)
    }
    /// Consumes and clears without output.
    pub fn cancel(self) {
        drop(self);
    }
    /// Explicitly declassifies the parameter-bound digest into a public type.
    pub fn finalize_public(
        self,
        authority: PublicDeclassification,
    ) -> Result<super::super::execution::Output<Sha512TDigest>, Error> {
        self.public(None, authority)
    }
    /// Declassifies after a final MSB-first bit tail.
    pub fn finalize_bits_public(
        self,
        input: BitString<'_>,
        authority: PublicDeclassification,
    ) -> Result<super::super::execution::Output<Sha512TDigest>, Error> {
        self.public(Some(input), authority)
    }
    fn public(
        mut self,
        input: Option<BitString<'_>>,
        _authority: PublicDeclassification,
    ) -> Result<super::super::execution::Output<Sha512TDigest>, Error> {
        self.finish(input)?;
        let digest = Sha512TDigest::computed(
            self.parameter,
            self.engine
                .owner
                .staged(self.parameter.output_bytes())
                .ok_or(Error::OutputLength)?,
        )
        .map_err(|_| Error::OutputLength)?;
        Ok(super::super::execution::Output {
            digest,
            report: self.engine.report,
        })
    }
    /// Transfers a parameter-bound, non-cloneable secret destination owner.
    /// Errors clear the entire destination; no public digest is constructed.
    pub fn finalize_secret(self, destination: &mut [u8]) -> Result<SecretOutput<'_>, Error> {
        let guard = begin(destination, self.parameter.output_bytes())?;
        self.secret(None, guard)
    }
    /// Transfers secret ownership after a final canonical MSB-first bit tail.
    pub fn finalize_bits_secret<'out>(
        self,
        input: BitString<'_>,
        destination: &'out mut [u8],
    ) -> Result<SecretOutput<'out>, Error> {
        let guard = begin(destination, self.parameter.output_bytes())?;
        self.secret(Some(input), guard)
    }
    fn secret<'out>(
        mut self,
        input: Option<BitString<'_>>,
        mut guard: SecretRegionInitialization<'out>,
    ) -> Result<SecretOutput<'out>, Error> {
        self.finish(input)?;
        guard.write(
            self.engine
                .owner
                .staged(self.parameter.output_bytes())
                .ok_or(Error::OutputLength)?,
        )?;
        Ok(SecretOutput {
            digest: Sha512TSecretDigest::from_region(self.parameter, guard.finish()?),
            report: self.engine.report,
        })
    }
    fn finish(&mut self, input: Option<BitString<'_>>) -> Result<(), Error> {
        self.engine.finish(
            input,
            self.parameter.output_bytes(),
            self.parameter.last_byte_mask(),
        )
    }
    /// One-shot complete-byte public declassification.
    pub fn hash_public(
        parameter: Sha512TBits,
        execution: Execution<'a>,
        input: &[u8],
        authority: PublicDeclassification,
    ) -> Result<super::super::execution::Output<Sha512TDigest>, Error> {
        let mut state = Self::new(parameter, execution)?;
        state.update(input)?;
        state.finalize_public(authority)
    }
    /// One-shot arbitrary-bit public declassification.
    pub fn hash_bits_public(
        parameter: Sha512TBits,
        execution: Execution<'a>,
        input: BitString<'_>,
        authority: PublicDeclassification,
    ) -> Result<super::super::execution::Output<Sha512TDigest>, Error> {
        Self::new(parameter, execution)?.finalize_bits_public(input, authority)
    }
    /// One-shot secret hashing; initialization guard precedes fallible work.
    pub fn hash_secret<'out>(
        parameter: Sha512TBits,
        execution: Execution<'a>,
        input: &[u8],
        destination: &'out mut [u8],
    ) -> Result<SecretOutput<'out>, Error> {
        let guard = begin(destination, parameter.output_bytes())?;
        let mut state = Self::new(parameter, execution)?;
        state.update(input)?;
        state.secret(None, guard)
    }
    /// One-shot arbitrary-bit secret hashing, retaining parameter identity.
    pub fn hash_bits_secret<'out>(
        parameter: Sha512TBits,
        execution: Execution<'a>,
        input: BitString<'_>,
        destination: &'out mut [u8],
    ) -> Result<SecretOutput<'out>, Error> {
        let guard = begin(destination, parameter.output_bytes())?;
        Self::new(parameter, execution)?.secret(Some(input), guard)
    }
}
impl crate::hardened::sealed::Registered for Sha512T<'_> {}
impl crate::HardenedSha2State for Sha512T<'_> {}

/// Parameter-bound affine secret digest and public execution observation.
pub struct SecretOutput<'a> {
    /// The sole secret owner; Drop clears the entire output destination.
    pub digest: Sha512TSecretDigest<'a>,
    /// Successful public work counts and selected route.
    pub report: Report,
}
