//! Private retained KMAC state over the existing accelerated cSHAKE component.
use super::kmac_accelerated_key::Key;
use super::packer::{Absorb, append_suffix};
use super::{Algorithm, Error, Fips202BitString};
use brynja_crypto_cpu::static_execution::Authority;
use brynja_mac_kmac::KmacError;
use sha3_accelerated_state::State as Cshake;
use sha3_stream::Algorithm as CshakeAlgorithm;

struct Sponge<'a>(Cshake<'a>);
impl Absorb for Sponge<'_> {
    fn absorb(&mut self, input: &[u8]) -> Result<(), KmacError> {
        self.0.update(input).map_err(|_| KmacError::StateConsumed)
    }
}
#[derive(PartialEq, Eq)]
enum Phase {
    Custom,
    Key,
    Message,
    Reader,
}
pub(super) enum State<'a> {
    Empty,
    Live(Core<'a>),
}
pub(super) struct Core<'a> {
    sponge: Sponge<'a>,
    key: Option<Key>,
    key_bits: u128,
    algorithm: Algorithm,
    phase: Phase,
}
impl<'a> State<'a> {
    pub(super) fn setup(
        authority: &'a Authority,
        algorithm: Algorithm,
        key: u128,
        custom: u128,
    ) -> Result<Self, Error> {
        let strength = if matches!(algorithm, Algorithm::Kmac128 | Algorithm::KmacXof128) {
            128
        } else {
            256
        };
        if key < strength {
            return Err(Error::Crypto);
        }
        let id = if strength == 128 {
            CshakeAlgorithm::Cshake128
        } else {
            CshakeAlgorithm::Cshake256
        };
        let mut state = Cshake::setup(authority, id, 32, custom).map_err(|_| Error::Crypto)?;
        state
            .setup_chunk(
                true,
                Fips202BitString::new(b"KMAC", 8).map_err(|_| Error::Bits)?,
            )
            .map_err(|_| Error::Crypto)?;
        Ok(Self::Live(Core {
            sponge: Sponge(state),
            key: None,
            key_bits: key,
            algorithm,
            phase: Phase::Custom,
        }))
    }
    pub(super) fn new(
        authority: &'a Authority,
        algorithm: Algorithm,
        key: Fips202BitString<'_>,
        custom: Fips202BitString<'_>,
    ) -> Result<Self, Error> {
        if key.as_bytes().len() > 1024 || custom.as_bytes().len() > 1024 {
            return Err(Error::Length);
        }
        let mut state = Self::setup(
            authority,
            algorithm,
            u128::try_from(key.bit_len()).map_err(|_| Error::Length)?,
            u128::try_from(custom.bit_len()).map_err(|_| Error::Length)?,
        )?;
        state.custom(custom)?;
        state.finish_custom()?;
        state.key(key)?;
        state.finish_setup(algorithm)?;
        Ok(state)
    }
    // Borrow retained storage; do not move the live cryptographic owner onto a
    // fresh stack frame on each operation. Failure/unwind drops its active state.
    fn run<T>(&mut self, f: impl FnOnce(&mut Core<'a>) -> Result<T, Error>) -> Result<T, Error> {
        let mut guard = Guard {
            state: self,
            complete: false,
        };
        let Self::Live(core) = guard.state else {
            return Err(Error::State);
        };
        let value = f(core)?;
        guard.complete = true;
        Ok(value)
    }
    pub(super) fn custom(&mut self, input: Fips202BitString<'_>) -> Result<(), Error> {
        self.run(|s| {
            if s.phase != Phase::Custom {
                return Err(Error::State);
            }
            if input.bit_len() != 0 {
                s.sponge
                    .0
                    .setup_chunk(false, input)
                    .map_err(|_| Error::Crypto)?;
            }
            Ok(())
        })
    }
    pub(super) fn finish_custom(&mut self) -> Result<(), Error> {
        self.run(|s| {
            if s.phase != Phase::Custom {
                return Err(Error::State);
            }
            s.sponge.0.finish_setup().map_err(|_| Error::Crypto)?;
            let rate = if matches!(s.algorithm, Algorithm::Kmac128 | Algorithm::KmacXof128) {
                168
            } else {
                136
            };
            s.key = Some(Key::new(&mut s.sponge.0, s.key_bits, rate)?);
            s.phase = Phase::Key;
            Ok(())
        })
    }
    pub(super) fn key(&mut self, input: Fips202BitString<'_>) -> Result<(), Error> {
        self.run(|s| {
            if s.phase != Phase::Key {
                return Err(Error::State);
            }
            s.key
                .as_mut()
                .ok_or(Error::State)?
                .push(&mut s.sponge.0, input)
        })
    }
    pub(super) fn finish_setup(&mut self, algorithm: Algorithm) -> Result<(), Error> {
        self.run(|s| {
            if s.phase != Phase::Key || s.algorithm != algorithm {
                return Err(Error::State);
            }
            s.key
                .as_mut()
                .ok_or(Error::State)?
                .finish(&mut s.sponge.0)?;
            s.key = None;
            s.phase = Phase::Message;
            Ok(())
        })
    }
    pub(super) fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        self.run(|s| {
            if s.phase != Phase::Message {
                return Err(Error::State);
            }
            s.sponge.absorb(input).map_err(|_| Error::Crypto)
        })
    }
    pub(super) fn fixed(
        &mut self,
        input: Fips202BitString<'_>,
        output: &mut [u8],
        last: u8,
    ) -> Result<(), Error> {
        self.run(|s| {
            if s.phase != Phase::Message || !s.algorithm.fixed() {
                return Err(Error::State);
            }
            let count = brynja_hash_sha3::Fips202Output::new(output, last)
                .map_err(|_| Error::Bits)?
                .bit_len();
            let bits = u128::try_from(count).map_err(|_| Error::Length)?;
            if bits
                < if s.algorithm == Algorithm::Kmac128 {
                    128
                } else {
                    256
                }
            {
                return Err(Error::Crypto);
            }
            Self::suffix(s, input, bits)?;
            s.sponge
                .0
                .squeeze(output, last, true)
                .map_err(|_| Error::Crypto)
        })?;
        *self = Self::Empty;
        Ok(())
    }
    fn suffix(s: &mut Core<'a>, input: Fips202BitString<'_>, bits: u128) -> Result<(), Error> {
        append_suffix(&mut s.sponge, Some(input), bits, |s, tail| {
            s.0.finish_xof(tail).map_err(|_| KmacError::StateConsumed)
        })
        .map_err(|_| Error::Crypto)
    }
    pub(super) fn finish_xof(&mut self, input: Fips202BitString<'_>) -> Result<(), Error> {
        self.run(|s| {
            if s.phase != Phase::Message || s.algorithm.fixed() {
                return Err(Error::State);
            }
            Self::suffix(s, input, 0)?;
            s.phase = Phase::Reader;
            Ok(())
        })
    }
    pub(super) fn squeeze(
        &mut self,
        output: &mut [u8],
        last: u8,
        terminal: bool,
    ) -> Result<(), Error> {
        self.run(|s| {
            if s.phase != Phase::Reader {
                return Err(Error::State);
            }
            s.sponge
                .0
                .squeeze(output, last, terminal)
                .map_err(|_| Error::Crypto)
        })?;
        if terminal {
            *self = Self::Empty;
        }
        Ok(())
    }
}
struct Guard<'s, 'a> {
    state: &'s mut State<'a>,
    complete: bool,
}
impl Drop for Guard<'_, '_> {
    fn drop(&mut self) {
        if !self.complete {
            *self.state = State::Empty;
        }
    }
}
