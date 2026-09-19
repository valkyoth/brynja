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
    pub(super) fn restart(&mut self) -> Result<(), Error> {
        self.cancel();
        self.session.check().map_err(Error::Backend)?;
        self.squeezing = false;
        self.failed = false;
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn cleared_for_test(&self) -> bool {
        self.memory
            .lanes
            .iter()
            .chain(&self.memory.message_count)
            .chain(&self.memory.output_count)
            .chain(&self.memory.suffix)
            .all(|byte| *byte == 0)
    }
    #[cfg(test)]
    pub(super) fn overflow_message_for_test(&mut self) {
        self.memory.message_count.fill(0xff);
    }
    #[cfg(test)]
    pub(super) fn overflow_output_for_test(&mut self) {
        self.memory.output_count.fill(0xff);
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
            brynja_core::xor_secret_byte_bits(target, byte, 0, 8, 0)
                .map_err(|_| Error::Terminal)?;
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
        let (complete, partial) = if input.is_byte_aligned() {
            (input.as_bytes(), None)
        } else {
            let (byte, complete) = input.as_bytes().split_last().ok_or(Error::Terminal)?;
            (complete, Some((byte, input.valid_bits_in_last_byte())))
        };
        engine.absorb(complete)?;
        engine.memory.suffix = [suffix, width];
        let mut bit_position = engine.position.saturating_mul(8);
        if let Some((byte, valid)) = partial {
            let target = engine
                .memory
                .lanes
                .get_mut(engine.position)
                .ok_or(Error::Terminal)?;
            brynja_core::xor_secret_byte_bits(target, byte, 0, valid, 0)
                .map_err(|_| Error::Terminal)?;
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
            brynja_core::xor_secret_byte_bits(
                target,
                &suffix,
                bit,
                1,
                u8::try_from(bit_position % 8).map_err(|_| Error::Terminal)?,
            )
            .map_err(|_| Error::Terminal)?;
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
        brynja_core::xor_secret_byte_bits(last, &0x80, 7, 1, 7).map_err(|_| Error::Terminal)?;
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
        let mut remaining = destination;
        while !remaining.is_empty() {
            if engine.position == engine.rate {
                engine.permute()?;
            }
            let count = engine
                .rate
                .checked_sub(engine.position)
                .filter(|count| *count != 0)
                .ok_or(Error::Terminal)?
                .min(remaining.len());
            let end = engine
                .position
                .checked_add(count)
                .ok_or(Error::LengthOverflow)?;
            let (output, rest) = remaining.split_at_mut(count);
            brynja_core::copy_secret_region(
                output,
                engine
                    .memory
                    .lanes
                    .get(engine.position..end)
                    .ok_or(Error::Terminal)?,
            )
            .map_err(|_| Error::SecretMemory)?;
            engine.position = end;
            remaining = rest;
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
