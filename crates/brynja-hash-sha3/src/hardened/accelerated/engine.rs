use super::{Error, KeccakSession, Report};
use crate::Fips202BitString;
use brynja_core::clear_owned_region;

pub(super) struct Memory {
    lanes: [u8; 200],
    message_count: [u8; 16],
    output_count: [u8; 16],
    suffix: [u8; 2],
}
impl Memory {
    fn new() -> Self {
        Self {
            lanes: [0; 200],
            message_count: [0; 16],
            output_count: [0; 16],
            suffix: [0; 2],
        }
    }
    #[inline(never)]
    fn wipe(&mut self) {
        let _ = clear_owned_region(&mut self.lanes);
        let _ = clear_owned_region(&mut self.message_count);
        let _ = clear_owned_region(&mut self.output_count);
        let _ = clear_owned_region(&mut self.suffix);
    }
}
impl Drop for Memory {
    fn drop(&mut self) {
        self.wipe();
    }
}

pub(super) struct Engine<'a> {
    memory: Memory,
    session: KeccakSession<'a>,
    rate: usize,
    position: usize,
    squeezing: bool,
    failed: bool,
    #[cfg(test)]
    pub(super) remaining_permutations: Option<usize>,
}

impl<'a> Engine<'a> {
    pub(super) fn new(session: KeccakSession<'a>, rate: usize) -> Result<Self, Error> {
        session.check().map_err(Error::Backend)?;
        if !matches!(rate, 72 | 104 | 136 | 144 | 168) {
            return Err(Error::OutputLength);
        }
        Ok(Self {
            memory: Memory::new(),
            session,
            rate,
            position: 0,
            squeezing: false,
            failed: false,
            #[cfg(test)]
            remaining_permutations: None,
        })
    }
    pub(super) fn report(&self) -> Report {
        self.session.report()
    }
    pub(super) fn cancel(&mut self) {
        self.failed = true;
        self.position = 0;
        self.memory.wipe();
    }
    pub(super) fn check(&self, squeezing: bool) -> Result<(), Error> {
        if self.failed || self.squeezing != squeezing {
            return Err(Error::Terminal);
        }
        self.session.check().map_err(Error::Backend)
    }
    pub(super) fn preflight(&self, bytes: usize) -> Result<(), Error> {
        self.check(true)?;
        read_count(&self.memory.output_count)
            .checked_add(bytes as u128)
            .ok_or(Error::LengthOverflow)
            .map(|_| ())
    }
    fn permute(&mut self) -> Result<(), Error> {
        #[cfg(test)]
        if let Some(remaining) = self.remaining_permutations.as_mut() {
            *remaining = remaining.checked_sub(1).ok_or(Error::Terminal)?;
        }
        self.session
            .permute(&mut self.memory.lanes)
            .map_err(Error::Backend)?;
        self.position = 0;
        Ok(())
    }
    fn absorb(&mut self, input: &[u8]) -> Result<(), Error> {
        self.check(false)?;
        let count = read_count(&self.memory.message_count)
            .checked_add(input.len() as u128)
            .ok_or(Error::LengthOverflow)?;
        for byte in input {
            let target = self
                .memory
                .lanes
                .get_mut(self.position)
                .ok_or(Error::Terminal)?;
            *target ^= *byte;
            self.position = self.position.checked_add(1).ok_or(Error::LengthOverflow)?;
            if self.position == self.rate {
                self.permute()?;
            }
        }
        write_count(&mut self.memory.message_count, count);
        Ok(())
    }
    pub(super) fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        let mut operation = Operation::new(self);
        operation.engine.absorb(input)?;
        operation.completed = true;
        Ok(())
    }
    pub(super) fn finish(
        &mut self,
        input: Fips202BitString<'_>,
        suffix: u8,
        width: u8,
    ) -> Result<(), Error> {
        let mut operation = Operation::new(self);
        let engine = &mut *operation.engine;
        let (complete, partial) = input.split();
        engine.absorb(complete)?;
        engine.memory.suffix = [suffix, width];
        let mut bit_position = engine.position.saturating_mul(8);
        if let Some((byte, valid)) = partial {
            let target = engine
                .memory
                .lanes
                .get_mut(engine.position)
                .ok_or(Error::Terminal)?;
            *target ^= byte;
            bit_position = bit_position.saturating_add(usize::from(valid));
        }
        for bit in 0..width {
            if bit_position == engine.rate.saturating_mul(8) {
                engine.permute()?;
                bit_position = 0;
            }
            let target = engine
                .memory
                .lanes
                .get_mut(bit_position / 8)
                .ok_or(Error::Terminal)?;
            *target ^= ((suffix >> bit) & 1) << (bit_position % 8);
            bit_position = bit_position.saturating_add(1);
        }
        if bit_position == engine.rate.saturating_mul(8) {
            engine.permute()?;
        }
        let last = engine
            .memory
            .lanes
            .get_mut(engine.rate.saturating_sub(1))
            .ok_or(Error::Terminal)?;
        *last ^= 0x80;
        engine.permute()?;
        engine.squeezing = true;
        let _ = clear_owned_region(&mut engine.memory.suffix);
        operation.completed = true;
        Ok(())
    }
    pub(super) fn read(&mut self, destination: &mut [u8]) -> Result<(), Error> {
        let mut operation = Operation::new(self);
        let engine = &mut *operation.engine;
        engine.preflight(destination.len())?;
        let count = read_count(&engine.memory.output_count)
            .checked_add(destination.len() as u128)
            .ok_or(Error::LengthOverflow)?;
        for byte in destination {
            if engine.position == engine.rate {
                engine.permute()?;
            }
            *byte = *engine
                .memory
                .lanes
                .get(engine.position)
                .ok_or(Error::Terminal)?;
            engine.position = engine
                .position
                .checked_add(1)
                .ok_or(Error::LengthOverflow)?;
        }
        write_count(&mut engine.memory.output_count, count);
        operation.completed = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests;

// Every error/unwind after entering an operation irreversibly clears the owner.
pub(super) struct Operation<'a, 'cpu> {
    pub(super) engine: &'a mut Engine<'cpu>,
    pub(super) completed: bool,
}
impl<'a, 'cpu> Operation<'a, 'cpu> {
    pub(super) fn new(engine: &'a mut Engine<'cpu>) -> Self {
        Self {
            engine,
            completed: false,
        }
    }
}
impl Drop for Operation<'_, '_> {
    fn drop(&mut self) {
        if !self.completed {
            self.engine.cancel();
        }
    }
}

fn read_count(bytes: &[u8; 16]) -> u128 {
    let mut value = 0;
    for (offset, byte) in bytes.iter().enumerate() {
        value |= u128::from(*byte) << offset.saturating_mul(8);
    }
    value
}
fn write_count(bytes: &mut [u8; 16], value: u128) {
    for (offset, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::try_from((value >> offset.saturating_mul(8)) & 255).unwrap_or_default();
    }
}
