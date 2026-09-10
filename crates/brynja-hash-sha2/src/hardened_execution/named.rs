use super::{
    Error, Execution, PublicDeclassification, Report, SecretOutput, begin, engine::Engine,
};
use crate::{BitString, hardened::HardenedSha2Owner};
use brynja_core::SecretRegionInitialization;

macro_rules! named {
    ($name:ident, $owner:expr, $wide:expr, $size:expr, $length:ty) => {
        /// Complete affine secret-bearing stream for this exact SHA-2 identity.
        /// Default constructors elsewhere remain portable. This type requires an
        /// explicit execution route; it has no reset, clone, debug or ordinary import.
        pub struct $name<'a> {
            engine: Engine<'a>,
        }
        impl<'a> $name<'a> {
            /// Exact algorithm output width in bytes.
            pub const OUTPUT_BYTES: usize = $size;
            /// Maximum complete-byte message domain.
            pub const MAX_MESSAGE_BYTES: $length = <$length>::MAX / 8;
            /// Maximum arbitrary-bit message domain.
            pub const MAX_MESSAGE_BITS: $length = <$length>::MAX;
            /// Rejects incompatible or unhealthy routes before accepting secrets.
            pub fn new(execution: Execution<'a>) -> Result<Self, Error> {
                Ok(Self {
                    engine: Engine::new($owner, execution, $wide, false)?,
                })
            }
            /// Complete bytes accepted successfully; public metadata.
            #[must_use]
            pub fn message_bytes(&self) -> $length {
                <$length>::try_from(self.engine.bytes()).unwrap_or(0)
            }
            /// Preflights a complete byte count without mutation.
            pub fn check_additional_bytes(&self, count: $length) -> Result<(), Error> {
                self.engine.check_bytes(count as u128)
            }
            /// Preflights a final bit count without mutation.
            pub fn check_additional_bits(&self, count: $length) -> Result<(), Error> {
                self.engine.check_bits(count as u128).map(|_| ())
            }
            /// Selected route and successful block work, never authority.
            #[must_use]
            pub const fn report(&self) -> Report {
                self.engine.report
            }
            /// Length errors preserve state; backend errors/unwind clear and
            /// permanently fail the stream. No partial-state retry or fallback.
            pub fn update(&mut self, input: &[u8]) -> Result<(), Error> {
                self.engine.update(input)
            }
            /// Consumes and clears the stream without output.
            pub fn cancel(self) {
                drop(self);
            }
            /// Consumes the state into an explicitly declassified public buffer.
            /// Errors preserve the entire public destination.
            pub fn finalize_public(
                self,
                destination: &mut [u8],
                authority: PublicDeclassification,
            ) -> Result<Report, Error> {
                self.public(None, destination, authority)
            }
            /// Consumes a final canonical MSB-first bit tail and declassifies output.
            pub fn finalize_bits_public(
                self,
                input: BitString<'_>,
                destination: &mut [u8],
                authority: PublicDeclassification,
            ) -> Result<Report, Error> {
                self.public(Some(input), destination, authority)
            }
            fn public(
                mut self,
                input: Option<BitString<'_>>,
                destination: &mut [u8],
                _authority: PublicDeclassification,
            ) -> Result<Report, Error> {
                if destination.len() != $size {
                    return Err(Error::OutputLength);
                }
                self.engine.finish(input, $size, 0xff)?;
                destination.copy_from_slice(&self.engine.owner.output_staging[..$size]);
                Ok(self.engine.report)
            }
            /// Consumes the stream into an erasing secret destination owner.
            /// Every error clears the entire destination, including wrong widths.
            pub fn finalize_secret(
                self,
                destination: &mut [u8],
            ) -> Result<SecretOutput<'_>, Error> {
                self.secret(None, begin(destination, $size)?)
            }
            /// Consumes a final bit tail into a typed secret destination.
            pub fn finalize_bits_secret<'out>(
                self,
                input: BitString<'_>,
                destination: &'out mut [u8],
            ) -> Result<SecretOutput<'out>, Error> {
                self.secret(Some(input), begin(destination, $size)?)
            }
            fn secret<'out>(
                mut self,
                input: Option<BitString<'_>>,
                mut guard: SecretRegionInitialization<'out>,
            ) -> Result<SecretOutput<'out>, Error> {
                self.engine.finish(input, $size, 0xff)?;
                guard.write(&self.engine.owner.output_staging[..$size])?;
                Ok(SecretOutput {
                    digest: guard.finish()?,
                    report: self.engine.report,
                })
            }
            /// One-shot complete-byte hashing with deliberate public output.
            pub fn hash_public(
                execution: Execution<'a>,
                input: &[u8],
                destination: &mut [u8],
                authority: PublicDeclassification,
            ) -> Result<Report, Error> {
                let mut state = Self::new(execution)?;
                state.update(input)?;
                state.finalize_public(destination, authority)
            }
            /// One-shot arbitrary-bit hashing with deliberate public output.
            pub fn hash_bits_public(
                execution: Execution<'a>,
                input: BitString<'_>,
                destination: &mut [u8],
                authority: PublicDeclassification,
            ) -> Result<Report, Error> {
                Self::new(execution)?.finalize_bits_public(input, destination, authority)
            }
            /// One-shot secret output; the destination guard precedes all
            /// fallible construction, input processing and finalization work.
            pub fn hash_secret<'out>(
                execution: Execution<'a>,
                input: &[u8],
                destination: &'out mut [u8],
            ) -> Result<SecretOutput<'out>, Error> {
                let guard = begin(destination, $size)?;
                let mut state = Self::new(execution)?;
                state.update(input)?;
                state.secret(None, guard)
            }
            /// One-shot arbitrary-bit secret output with the same failure clearing.
            pub fn hash_bits_secret<'out>(
                execution: Execution<'a>,
                input: BitString<'_>,
                destination: &'out mut [u8],
            ) -> Result<SecretOutput<'out>, Error> {
                let guard = begin(destination, $size)?;
                Self::new(execution)?.secret(Some(input), guard)
            }
        }
        impl crate::hardened::sealed::Registered for $name<'_> {}
        impl crate::HardenedSha2State for $name<'_> {}
    };
}

named!(
    Sha224,
    HardenedSha2Owner::new32(crate::sha224::INITIAL_STATE),
    false,
    28,
    u64
);
named!(
    Sha256,
    HardenedSha2Owner::new32(crate::sha256::INITIAL_STATE),
    false,
    32,
    u64
);
named!(
    Sha384,
    HardenedSha2Owner::new64(crate::sha384::INITIAL_STATE),
    true,
    48,
    u128
);
named!(
    Sha512,
    HardenedSha2Owner::new64(crate::sha512::INITIAL_STATE),
    true,
    64,
    u128
);
named!(
    Sha512_224,
    HardenedSha2Owner::new64(crate::sha512_t::SHA512_224_INITIAL_STATE),
    true,
    28,
    u128
);
named!(
    Sha512_256,
    HardenedSha2Owner::new64(crate::sha512_t::SHA512_256_INITIAL_STATE),
    true,
    32,
    u128
);
