//! Sequenced setup protocol. Lengths are declared public, never queried from
//! secret state. Each fragment is bounded independently of the total length.
use super::{Algorithm, Error, Owner, Phase, State};
use brynja_mac_kmac::{Fips202BitString, Kmac128Setup, Kmac256Setup};

impl State {
    pub(super) fn setup(algorithm: Algorithm, key: u128, custom: u128) -> Result<Self, Error> {
        match algorithm {
            Algorithm::Kmac128 | Algorithm::KmacXof128 => {
                Kmac128Setup::new(key, custom).map(Self::Setup128)
            }
            Algorithm::Kmac256 | Algorithm::KmacXof256 => {
                Kmac256Setup::new(key, custom).map(Self::Setup256)
            }
        }
        .map_err(|_| Error::Crypto)
    }
    pub(super) fn custom(&mut self, input: Fips202BitString<'_>) -> Result<(), Error> {
        match self {
            Self::Setup128(s) => s.customization(input),
            Self::Setup256(s) => s.customization(input),
            _ => return Err(Error::State),
        }
        .map_err(|_| Error::Crypto)
    }
    pub(super) fn finish_custom(&mut self) -> Result<(), Error> {
        match self {
            Self::Setup128(s) => s.finish_customization(),
            Self::Setup256(s) => s.finish_customization(),
            _ => return Err(Error::State),
        }
        .map_err(|_| Error::Crypto)
    }
    pub(super) fn key(&mut self, input: Fips202BitString<'_>) -> Result<(), Error> {
        match self {
            Self::Setup128(s) => s.key(input),
            Self::Setup256(s) => s.key(input),
            _ => return Err(Error::State),
        }
        .map_err(|_| Error::Crypto)
    }
    pub(super) fn finish_setup(&mut self, algorithm: Algorithm) -> Result<(), Error> {
        *self = match (core::mem::replace(self, Self::Empty), algorithm) {
            (Self::Setup128(s), Algorithm::Kmac128) => s.finish().map(Self::A),
            (Self::Setup256(s), Algorithm::Kmac256) => s.finish().map(Self::B),
            (Self::Setup128(s), Algorithm::KmacXof128) => s.finish_xof().map(Self::X),
            (Self::Setup256(s), Algorithm::KmacXof256) => s.finish_xof().map(Self::Y),
            _ => return Err(Error::Identity),
        }
        .map_err(|_| Error::Crypto)?;
        Ok(())
    }
}

impl Owner {
    pub fn begin_setup(
        &mut self,
        sequence: u64,
        identity: u64,
        key_bits: u128,
        custom_bits: u128,
    ) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::Empty])?;
        let algorithm = Algorithm::decode(identity)?;
        op.owner.state = State::setup(algorithm, key_bits, custom_bits)?;
        op.owner.algorithm = Some(algorithm);
        op.owner.phase = Phase::Custom;
        op.complete = true;
        Ok(())
    }
    /// Consume the exact retained bit string as the next key, but stream S.
    /// No host-supplied replacement key or key length is accepted on this path.
    pub fn rekey_setup(
        &mut self,
        sequence: u64,
        identity: u64,
        custom_bits: u128,
    ) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::RetainedFinal, Phase::RetainedMore])?;
        let algorithm = Algorithm::decode(identity)?;
        let key = Fips202BitString::new(
            op.owner.output.get(..op.owner.width).ok_or(Error::Length)?,
            op.owner.last,
        )
        .map_err(|_| Error::Bits)?;
        let count = u128::try_from(key.bit_len()).map_err(|_| Error::Length)?;
        op.owner.state = State::setup(algorithm, count, custom_bits)?;
        op.owner.algorithm = Some(algorithm);
        op.owner.phase = Phase::CustomRetained;
        op.complete = true;
        Ok(())
    }
    pub fn customization(
        &mut self,
        sequence: u64,
        input: Fips202BitString<'_>,
    ) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::Custom, Phase::CustomRetained])?;
        if input.as_bytes().len() > 1024 {
            return Err(Error::Length);
        }
        op.owner.state.custom(input)?;
        op.complete = true;
        Ok(())
    }
    pub fn finish_customization(&mut self, sequence: u64) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::Custom, Phase::CustomRetained])?;
        op.owner.state.finish_custom()?;
        if op.owner.phase == Phase::CustomRetained {
            let key = Fips202BitString::new(
                op.owner.output.get(..op.owner.width).ok_or(Error::Length)?,
                op.owner.last,
            )
            .map_err(|_| Error::Bits)?;
            op.owner.state.key(key)?;
            op.owner
                .state
                .finish_setup(op.owner.algorithm.ok_or(Error::Identity)?)?;
            op.owner.clear_output();
            op.owner.phase = Phase::Streaming;
        } else {
            op.owner.phase = Phase::Key;
        }
        op.complete = true;
        Ok(())
    }
    pub fn key(&mut self, sequence: u64, input: Fips202BitString<'_>) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::Key])?;
        if input.as_bytes().len() > 1024 {
            return Err(Error::Length);
        }
        op.owner.state.key(input)?;
        op.complete = true;
        Ok(())
    }
    pub fn finish_setup(&mut self, sequence: u64) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::Key])?;
        op.owner
            .state
            .finish_setup(op.owner.algorithm.ok_or(Error::Identity)?)?;
        op.owner.phase = Phase::Streaming;
        op.complete = true;
        Ok(())
    }
}
