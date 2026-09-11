use super::super::output::{begin_secret, finish_secret};
use super::reader::Stage;
use super::{
    Error, HardenedSha3SecretOutput, KeccakSession, Reader, Report, Sha3PublicDeclassification,
    engine::Engine,
};
use crate::Fips202BitString;

macro_rules! fixed {
    ($name:ident, $rate:literal, $width:literal) => {
        /// Affine hardened SHA-3 absorbing owner on one selected CPU backend.
        pub struct $name<'a> {
            engine: Engine<'a>,
        }
        impl<'a> $name<'a> {
            /// Creates an empty owner, retaining the exact hardened session.
            pub fn new(session: KeccakSession<'a>) -> Result<Self, Error> {
                Ok(Self {
                    engine: Engine::new(session, $rate)?,
                })
            }
            /// Observes the selected backend and its current health.
            pub fn report(&self) -> Report {
                self.engine.report()
            }
            /// Absorbs bytes; execution errors irreversibly clear this owner.
            pub fn update(&mut self, input: &[u8]) -> Result<(), Error> {
                self.engine.update(input)
            }
            /// Clears the owner and prohibits further work.
            pub fn cancel(&mut self) {
                self.engine.cancel();
            }
            /// Consumes state and declassifies one complete digest.
            pub fn finalize_public(
                self,
                output: &mut [u8],
                authority: Sha3PublicDeclassification,
            ) -> Result<(), Error> {
                self.finalize_bits_public(super::empty()?, output, authority)
            }
            /// Consumes state and transfers one complete typed secret digest.
            pub fn finalize_secret<'out>(
                self,
                output: &'out mut [u8],
            ) -> Result<HardenedSha3SecretOutput<'out>, Error> {
                self.finalize_bits_secret(super::empty()?, output)
            }
            /// Consumes one canonical final bit string and declassifies the digest.
            pub fn finalize_bits_public(
                mut self,
                input: Fips202BitString<'_>,
                output: &mut [u8],
                authority: Sha3PublicDeclassification,
            ) -> Result<(), Error> {
                if output.len() != $width {
                    return Err(Error::OutputLength);
                }
                self.engine.finish(input, 0x06, 3)?;
                Reader {
                    engine: self.engine,
                }
                .squeeze_public(output, authority)
            }
            /// Consumes a final bit string. Any failure clears the full secret destination.
            pub fn finalize_bits_secret<'out>(
                mut self,
                input: Fips202BitString<'_>,
                output: &'out mut [u8],
            ) -> Result<HardenedSha3SecretOutput<'out>, Error> {
                // Acquire destination cleanup before any secret finalization,
                // including operations that may unwind inside an instruction routine.
                let length = output.len();
                let mut initialization = begin_secret(output)?;
                if length != $width {
                    return Err(Error::OutputLength);
                }
                self.engine.finish(input, 0x06, 3)?;
                let mut stage = Stage([0; 168]);
                let buffer = stage.0.get_mut(..$width).ok_or(Error::OutputLength)?;
                self.engine.read(buffer)?;
                initialization
                    .as_mut()
                    .ok_or(Error::SecretMemory)?
                    .write(buffer)
                    .map_err(|_| Error::SecretMemory)?;
                finish_secret(initialization).map_err(Error::from)
            }
        }
    };
}
fixed!(Sha3_224, 144, 28);
fixed!(Sha3_256, 136, 32);
fixed!(Sha3_384, 104, 48);
fixed!(Sha3_512, 72, 64);
