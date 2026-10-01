//! Owner-side sequenced setup over the explicit accelerated authority.
use super::{Algorithm, Error, Fips202BitString, Owner, Phase, State};
impl Owner<'_> {
    pub fn begin_setup(
        &mut self,
        sequence: u64,
        identity: u64,
        key_bits: u128,
        custom_bits: u128,
    ) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::Empty])?;
        let algorithm = Algorithm::decode(identity)?;
        op.owner.state = State::setup(op.owner.authority, algorithm, key_bits, custom_bits)?;
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
        op.owner.state = State::setup(op.owner.authority, algorithm, count, custom_bits)?;
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
