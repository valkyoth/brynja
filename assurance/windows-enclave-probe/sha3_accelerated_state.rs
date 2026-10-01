//! Private AVX2 state adapter. The builder compiles the existing hardened
//! engine source unchanged; this is not a second permutation implementation.
#![no_std]
#![forbid(unsafe_code)]

use brynja_core::{clear_owned_region, copy_secret_region};
use brynja_crypto_cpu::static_execution::{Authority, Kernel};
pub use brynja_hash_sha3::Fips202BitString;
pub use brynja_hash_sha3::hardened_execution::{Error, KeccakSession, Report};
use sha3_stream::Algorithm;
#[allow(dead_code)] // The shared engine also supplies reader APIs not needed here.
#[path = "keccak_engine.rs"]
mod engine;
mod sha3_accelerated_prefix;
use engine::Engine;
use sha3_accelerated_prefix::Prefix;

pub enum State<'a> {
    Empty,
    Live(Core<'a>),
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Setup,
    Absorbing,
    Squeezing,
    Dead,
}
pub struct Core<'a> {
    engine: Engine<'a>,
    prefix: Option<Prefix>,
    phase: Phase,
    fixed: Option<usize>,
    suffix: u8,
    suffix_width: u8,
}
struct Operation<'s, 'a> {
    core: &'s mut Core<'a>,
    complete: bool,
}
impl Drop for Operation<'_, '_> {
    fn drop(&mut self) {
        if !self.complete {
            self.core.clear();
        }
    }
}
impl Core<'_> {
    fn clear(&mut self) {
        self.engine.cancel();
        self.prefix = None;
        self.phase = Phase::Dead;
    }
    fn run<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T, Error>) -> Result<T, Error> {
        let mut op = Operation {
            core: self,
            complete: false,
        };
        let result = f(op.core)?;
        op.complete = true;
        Ok(result)
    }
    fn check(&self, phase: Phase) -> Result<(), Error> {
        if self.phase != phase {
            return Err(Error::Terminal);
        }
        self.engine.check(phase == Phase::Squeezing)
    }
}
impl Drop for Core<'_> {
    fn drop(&mut self) {
        self.clear();
    }
}
struct Scratch([u8; 1024]);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = clear_owned_region(&mut self.0);
    }
}

impl<'a> State<'a> {
    fn core(&mut self) -> Result<&mut Core<'a>, Error> {
        match self {
            Self::Live(core) => Ok(core),
            Self::Empty => Err(Error::Terminal),
        }
    }
    fn initial(authority: &'a Authority, algorithm: Algorithm) -> Result<Core<'a>, Error> {
        if authority.report().kernel != Kernel::X86Keccak {
            return Err(Error::PrefixEncoding);
        }
        let session = KeccakSession::from_static(authority).map_err(Error::Backend)?;
        let rate = match algorithm {
            Algorithm::Sha3_224 => 144,
            Algorithm::Sha3_256 => 136,
            Algorithm::Sha3_384 => 104,
            Algorithm::Sha3_512 => 72,
            Algorithm::Shake128 | Algorithm::Cshake128 => 168,
            Algorithm::Shake256 | Algorithm::Cshake256 => 136,
        };
        Ok(Core {
            engine: Engine::new(session, rate)?,
            prefix: None,
            phase: Phase::Absorbing,
            fixed: algorithm.fixed_width(),
            suffix: if algorithm.fixed_width().is_some() {
                0x06
            } else {
                0x1f
            },
            suffix_width: if algorithm.fixed_width().is_some() {
                3
            } else {
                5
            },
        })
    }
    pub fn setup(
        authority: &'a Authority,
        algorithm: Algorithm,
        name: u128,
        custom: u128,
    ) -> Result<Self, Error> {
        if !matches!(algorithm, Algorithm::Cshake128 | Algorithm::Cshake256) {
            return Err(Error::PrefixEncoding);
        }
        let mut core = Self::initial(authority, algorithm)?;
        let rate = if algorithm == Algorithm::Cshake128 {
            168
        } else {
            136
        };
        core.prefix = Some(Prefix::new(&mut core.engine, rate, name, custom)?);
        core.phase = Phase::Setup;
        core.suffix = if name != 0 || custom != 0 { 0x04 } else { 0x1f };
        core.suffix_width = if name != 0 || custom != 0 { 3 } else { 5 };
        Ok(Self::Live(core))
    }
    pub fn new(
        authority: &'a Authority,
        algorithm: Algorithm,
        name: Fips202BitString<'_>,
        custom: Fips202BitString<'_>,
    ) -> Result<Self, Error> {
        if name.bit_len() > 8192 || custom.bit_len() > 8192 {
            return Err(Error::OutputLength);
        }
        if !matches!(algorithm, Algorithm::Cshake128 | Algorithm::Cshake256) {
            if name.bit_len() != 0 || custom.bit_len() != 0 {
                return Err(Error::PrefixEncoding);
            }
            return Self::initial(authority, algorithm).map(Self::Live);
        }
        let mut state = Self::setup(
            authority,
            algorithm,
            u128::try_from(name.bit_len()).map_err(|_| Error::LengthOverflow)?,
            u128::try_from(custom.bit_len()).map_err(|_| Error::LengthOverflow)?,
        )?;
        if name.bit_len() != 0 {
            state.setup_chunk(true, name)?;
        }
        if custom.bit_len() != 0 {
            state.setup_chunk(false, custom)?;
        }
        state.finish_setup()?;
        Ok(state)
    }
    pub fn setup_chunk(&mut self, name: bool, input: Fips202BitString<'_>) -> Result<(), Error> {
        self.core()?.run(|core| {
            core.check(Phase::Setup)?;
            core.prefix
                .as_mut()
                .ok_or(Error::Terminal)?
                .push(&mut core.engine, name, input)
        })
    }
    pub fn finish_setup(&mut self) -> Result<(), Error> {
        self.core()?.run(|core| {
            core.check(Phase::Setup)?;
            core.prefix.as_ref().ok_or(Error::Terminal)?.complete()?;
            core.prefix = None;
            core.phase = Phase::Absorbing;
            Ok(())
        })
    }
    pub fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        self.core()?.run(|core| {
            core.check(Phase::Absorbing)?;
            core.engine.update(input)
        })
    }
    pub fn finish_fixed(
        &mut self,
        input: Fips202BitString<'_>,
        output: &mut [u8],
    ) -> Result<(), Error> {
        self.core()?.run(|core| {
            core.check(Phase::Absorbing)?;
            if core.fixed != Some(output.len()) {
                return Err(Error::OutputLength);
            }
            core.engine.finish(input, core.suffix, core.suffix_width)?;
            let mut staging = Scratch([0; 1024]);
            let bytes = staging
                .0
                .get_mut(..output.len())
                .ok_or(Error::OutputLength)?;
            core.engine.read(bytes)?;
            copy_secret_region(output, bytes).map_err(|_| Error::SecretMemory)?;
            core.clear();
            Ok(())
        })?;
        *self = Self::Empty;
        Ok(())
    }
    pub fn finish_xof(&mut self, input: Fips202BitString<'_>) -> Result<(), Error> {
        self.core()?.run(|core| {
            core.check(Phase::Absorbing)?;
            if core.fixed.is_some() {
                return Err(Error::Terminal);
            }
            core.engine.finish(input, core.suffix, core.suffix_width)?;
            core.phase = Phase::Squeezing;
            Ok(())
        })
    }
    pub fn squeeze(&mut self, output: &mut [u8], last: u8, terminal: bool) -> Result<(), Error> {
        self.core()?.run(|core| {
            core.check(Phase::Squeezing)?;
            if (!terminal && last != if output.is_empty() { 0 } else { 8 })
                || (output.is_empty() && last != 0)
            {
                return Err(Error::OutputLength);
            }
            let mut staging = Scratch([0; 1024]);
            let bytes = staging
                .0
                .get_mut(..output.len())
                .ok_or(Error::OutputLength)?;
            let _ = brynja_hash_sha3::Fips202Output::new(bytes, last)
                .map_err(|_| Error::OutputLength)?;
            core.engine.read(bytes)?;
            if (1..8).contains(&last) {
                brynja_core::apply_secret_byte_mask(
                    bytes.last_mut().ok_or(Error::OutputLength)?,
                    u8::MAX
                        .checked_shr(u32::from(
                            8_u8.checked_sub(last).ok_or(Error::OutputLength)?,
                        ))
                        .ok_or(Error::OutputLength)?,
                    0,
                );
            }
            copy_secret_region(output, bytes).map_err(|_| Error::SecretMemory)?;
            if terminal {
                core.clear();
            }
            Ok(())
        })?;
        if terminal {
            *self = Self::Empty;
        }
        Ok(())
    }
}
