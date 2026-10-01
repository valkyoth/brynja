//! ParallelHash domain setup over the unchanged accelerated cSHAKE engine.
use super::{Bits, Error};
use brynja_crypto_cpu::static_execution::Authority;
use sha3_accelerated_state::State as Cshake;
use sha3_stream::Algorithm;

pub(super) enum State<'a> {
    Empty,
    Live(Cshake<'a>),
}
impl<'a> State<'a> {
    pub(super) fn leaf(authority: &'a Authority, identity: u64) -> Result<Self, Error> {
        let algorithm = match identity {
            1 | 3 => Algorithm::Shake128,
            2 | 4 => Algorithm::Shake256,
            _ => return Err(Error::Identity),
        };
        let empty = Bits::new(&[], 0).map_err(|_| Error::Bits)?;
        Cshake::new(authority, algorithm, empty, empty)
            .map(Self::Live)
            .map_err(|_| Error::Crypto)
    }
    pub(super) fn setup(
        authority: &'a Authority,
        identity: u64,
        bits: u128,
    ) -> Result<Self, Error> {
        let algorithm = match identity {
            1 | 3 => Algorithm::Cshake128,
            2 | 4 => Algorithm::Cshake256,
            _ => return Err(Error::Identity),
        };
        let mut state = Cshake::setup(authority, algorithm, 96, bits).map_err(|_| Error::Crypto)?;
        state
            .setup_chunk(
                true,
                Bits::new(b"ParallelHash", 8).map_err(|_| Error::Bits)?,
            )
            .map_err(|_| Error::Crypto)?;
        Ok(Self::Live(state))
    }
    fn live(&mut self) -> Result<&mut Cshake<'a>, Error> {
        match self {
            Self::Live(state) => Ok(state),
            Self::Empty => Err(Error::State),
        }
    }
    pub(super) fn custom(&mut self, input: Bits<'_>) -> Result<(), Error> {
        // Empty updates are allowed by the ParallelHash API, but the prefix worker
        // only accepts nonempty chunks while a declared field has remaining bits.
        if input.bit_len() == 0 {
            return Ok(());
        }
        self.live()?
            .setup_chunk(false, input)
            .map_err(|_| Error::Crypto)
    }
    pub(super) fn finish_custom(&mut self) -> Result<(), Error> {
        self.live()?.finish_setup().map_err(|_| Error::Crypto)
    }
    pub(super) fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        self.live()?.update(input).map_err(|_| Error::Crypto)
    }
    pub(super) fn finish(&mut self, tail: Bits<'_>) -> Result<(), Error> {
        self.live()?.finish_xof(tail).map_err(|_| Error::Crypto)
    }
    pub(super) fn squeeze(
        &mut self,
        output: &mut [u8],
        last: u8,
        terminal: bool,
    ) -> Result<(), Error> {
        self.live()?
            .squeeze(output, last, terminal)
            .map_err(|_| Error::Crypto)
    }
}
