use super::{Error, KeccakSession, Reader, Report, engine::Engine};
use crate::{Fips202BitString, sp800185::absorb_cshake_prefix};

macro_rules! operations {
    () => {
        /// Observes the exact selected backend and its health.
        pub fn report(&self) -> Report {
            self.engine.report()
        }
        /// Absorbs complete bytes; failures irreversibly clear the owner.
        pub fn update(&mut self, input: &[u8]) -> Result<(), Error> {
            self.engine.update(input)
        }
        /// Irreversibly clears the absorbing owner.
        pub fn cancel(&mut self) {
            self.engine.cancel();
        }
        /// Changes phase without moving or exporting the owned sponge state.
        /// Further absorption is terminally rejected. Intended for keyed owners
        /// that must retain their erasing source throughout the transition.
        pub fn enter_squeezing_in_place(
            &mut self,
            input: Fips202BitString<'_>,
        ) -> Result<(), Error> {
            self.engine.finish(input, self.suffix, self.width)
        }
        /// Reads typed secret output after the in-place transition.
        pub fn squeeze_secret_in_place<'out>(
            &mut self,
            output: &'out mut [u8],
        ) -> Result<super::HardenedSha3SecretOutput<'out>, Error> {
            self.engine.read_secret(output, 8)
        }
        /// Declassifies output transactionally after the in-place transition.
        /// Scratch is treated as secret and entirely erased on every exit.
        pub fn squeeze_public_in_place(
            &mut self,
            output: &mut [u8],
            scratch: &mut [u8],
            authority: super::Sha3PublicDeclassification,
        ) -> Result<(), Error> {
            self.engine.read_public(output, scratch, authority)
        }
        /// Writes a canonical final partial secret byte then erases the source.
        /// The owner cannot resume squeezing or absorbing, even on failure.
        pub fn squeeze_final_bits_secret_in_place<'out>(
            &mut self,
            output: &'out mut [u8],
            valid_bits: u8,
        ) -> Result<super::HardenedSha3SecretOutput<'out>, Error> {
            if output.is_empty() && valid_bits != 0 {
                self.engine.cancel();
                return Err(Error::OutputLength);
            }
            let result = self.engine.read_secret(output, valid_bits);
            self.engine.cancel();
            result
        }
        /// Declassifies canonical final output bits and irreversibly clears the
        /// source. Scratch is cleared on every exit; errors preserve output.
        pub fn squeeze_final_bits_public_in_place(
            &mut self,
            output: crate::Fips202Output<'_>,
            scratch: &mut [u8],
            authority: super::Sha3PublicDeclassification,
        ) -> Result<(), Error> {
            let (bytes, valid) = output.into_parts();
            let result = self.engine.read_public(bytes, scratch, authority);
            self.engine.cancel();
            result?;
            if valid != 0
                && valid != 8
                && let Some(last) = bytes.last_mut()
            {
                *last &= u8::MAX >> 8_u8.saturating_sub(valid);
            }
            Ok(())
        }
        /// Consumes absorption into a hardened XOF reader without a state snapshot.
        pub fn finalize_xof(self) -> Result<Reader<'a>, Error> {
            self.finalize_bits_xof(super::empty()?)
        }
        /// Consumes a canonical final message bit string into a retained reader.
        pub fn finalize_bits_xof(
            mut self,
            input: Fips202BitString<'_>,
        ) -> Result<Reader<'a>, Error> {
            self.engine.finish(input, self.suffix, self.width)?;
            Ok(Reader {
                engine: self.engine,
            })
        }
    };
}
macro_rules! shake {
    ($name:ident, $rate:literal) => {
        /// Hardened accelerated SHAKE absorption with affine reader transition.
        pub struct $name<'a> {
            engine: Engine<'a>,
            suffix: u8,
            width: u8,
        }
        impl<'a> $name<'a> {
            /// Retains a fully authorized hardened Keccak session.
            pub fn new(session: KeccakSession<'a>) -> Result<Self, Error> {
                Ok(Self {
                    engine: Engine::new(session, $rate)?,
                    suffix: 0x1f,
                    width: 5,
                })
            }
            operations!();
        }
    };
}
macro_rules! cshake {
    ($name:ident, $rate:literal) => {
        /// Hardened accelerated cSHAKE; N/S and message may be secret-bearing.
        pub struct $name<'a> {
            engine: Engine<'a>,
            suffix: u8,
            width: u8,
        }
        impl<'a> $name<'a> {
            /// Absorbs byte-oriented function name and customization on the selected route.
            pub fn new(
                session: KeccakSession<'a>,
                function_name: &[u8],
                customization: &[u8],
            ) -> Result<Self, Error> {
                let n = Fips202BitString::new(
                    function_name,
                    if function_name.is_empty() { 0 } else { 8 },
                )
                .map_err(|_| Error::PrefixEncoding)?;
                let s = Fips202BitString::new(
                    customization,
                    if customization.is_empty() { 0 } else { 8 },
                )
                .map_err(|_| Error::PrefixEncoding)?;
                Self::new_bits(session, n, s)
            }
            /// Absorbs arbitrary-bit N/S. Empty N/S preserves SHAKE equivalence.
            pub fn new_bits(
                session: KeccakSession<'a>,
                function_name: Fips202BitString<'_>,
                customization: Fips202BitString<'_>,
            ) -> Result<Self, Error> {
                let mut engine = Engine::new(session, $rate)?;
                let mut backend_error = None;
                let customized =
                    absorb_cshake_prefix($rate, function_name, customization, |bytes| {
                        engine.update(bytes).map_err(|error| {
                            backend_error = Some(error);
                        })
                    })
                    .map_err(|()| backend_error.unwrap_or(Error::PrefixEncoding))?;
                Ok(Self {
                    engine,
                    suffix: if customized { 0x04 } else { 0x1f },
                    width: if customized { 3 } else { 5 },
                })
            }
            operations!();
        }
    };
}
shake!(Shake128, 168);
shake!(Shake256, 136);
cshake!(Cshake128, 168);
cshake!(Cshake256, 136);
