use super::{Error, Execution, Report};
use crate::{BitString, hardened::HardenedSha2Owner};
use brynja_core::clear_owned_region;

pub(super) struct Engine<'a> {
    pub(super) owner: HardenedSha2Owner,
    pub(super) report: Report,
    execution: Execution<'a>,
    wide: bool,
    failed: bool,
}

impl<'a> Engine<'a> {
    pub(super) fn new(
        owner: HardenedSha2Owner,
        execution: Execution<'a>,
        wide: bool,
        general: bool,
    ) -> Result<Self, Error> {
        execution.check(wide)?;
        let report = Report {
            route: execution.route(),
            message_blocks: 0,
            padding_blocks: 0,
            portable_iv_blocks: u128::from(general),
        };
        Ok(Self {
            owner,
            report,
            execution,
            wide,
            failed: false,
        })
    }
    pub(super) fn bytes(&self) -> u128 {
        if self.wide {
            self.owner.message_bytes64()
        } else {
            u128::from(self.owner.message_bytes32())
        }
    }
    pub(super) fn check_bytes(&self, count: u128) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        let maximum = if self.wide {
            u128::MAX / 8
        } else {
            u128::from(u64::MAX / 8)
        };
        self.bytes()
            .checked_add(count)
            .filter(|v| *v <= maximum)
            .map(|_| ())
            .ok_or(Error::MessageTooLong)
    }
    pub(super) fn check_bits(&self, count: u128) -> Result<u128, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        let maximum = if self.wide {
            u128::MAX
        } else {
            u128::from(u64::MAX)
        };
        self.bytes()
            .checked_mul(8)
            .and_then(|v| v.checked_add(count))
            .filter(|v| *v <= maximum)
            .ok_or(Error::MessageTooLong)
    }
    pub(super) fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        self.check_bytes(input.len() as u128)?;
        if let Err(error) = self.execution.check(self.wide) {
            self.owner.wipe();
            self.failed = true;
            return Err(error);
        }
        let total = self
            .bytes()
            .checked_add(input.len() as u128)
            .ok_or(Error::MessageTooLong)?;
        let block_bytes: usize = if self.wide { 128 } else { 64 };
        let prospective = (input.len() as u128)
            .checked_add(self.owner.buffer_len() as u128)
            .and_then(|count| count.checked_div(block_bytes as u128))
            .ok_or(Error::MessageTooLong)?;
        self.report
            .message_blocks
            .checked_add(prospective)
            .ok_or(Error::MessageTooLong)?;
        let mut guard = Update {
            owner: &mut self.owner,
            failed: &mut self.failed,
            completed: false,
        };
        let mut remaining = input;
        while !remaining.is_empty() {
            let offset = guard.owner.buffer_len();
            let copied = core::cmp::min(
                block_bytes.checked_sub(offset).ok_or(Error::Failed)?,
                remaining.len(),
            );
            let end = offset.checked_add(copied).ok_or(Error::Failed)?;
            guard
                .owner
                .partial_input
                .get_mut(offset..end)
                .ok_or(Error::Failed)?
                .copy_from_slice(remaining.get(..copied).ok_or(Error::Failed)?);
            guard.owner.set_buffer_len(end).map_err(|_| Error::Failed)?;
            remaining = remaining.get(copied..).ok_or(Error::Failed)?;
            if guard.owner.buffer_len() == block_bytes {
                copy_prefix(
                    &mut guard.owner.block_copy,
                    &guard.owner.partial_input,
                    block_bytes,
                )?;
                self.execution.compress(self.wide, guard.owner)?;
                self.report.message_blocks = self
                    .report
                    .message_blocks
                    .checked_add(1)
                    .ok_or(Error::MessageTooLong)?;
                let _ = clear_owned_region(&mut guard.owner.partial_input);
                guard.owner.set_buffer_len(0).map_err(|_| Error::Failed)?;
            }
        }
        if self.wide {
            guard.owner.message_length = total.to_be_bytes();
        } else {
            guard.owner.message_length[..8].copy_from_slice(
                &u64::try_from(total)
                    .map_err(|_| Error::MessageTooLong)?
                    .to_be_bytes(),
            );
        }
        guard.completed = true;
        Ok(())
    }
    pub(super) fn finish(
        &mut self,
        input: Option<BitString<'_>>,
        length: usize,
        mask: u8,
    ) -> Result<(), Error> {
        let additional = input.map_or(0, |bits| bits.bit_len() as u128);
        let total_bits = self.check_bits(additional)?;
        self.execution.check(self.wide)?;
        let partial = if let Some(input) = input {
            let (bytes, tail) = input.split();
            self.update(bytes)?;
            tail
        } else {
            None
        };
        let block_bytes = if self.wide { 128 } else { 64 };
        let length_start = if self.wide { 112 } else { 56 };
        let buffered = self.owner.buffer_len();
        self.owner.phase[0] = 1;
        copy_prefix(
            &mut self.owner.padding_block,
            &self.owner.partial_input,
            buffered,
        )?;
        *self
            .owner
            .padding_block
            .get_mut(buffered)
            .ok_or(Error::Failed)? = partial.map_or(0x80, |(byte, bits)| byte | (0x80 >> bits));
        if buffered >= length_start {
            self.padding(block_bytes)?;
            let _ = clear_owned_region(&mut self.owner.padding_block);
        }
        if self.wide {
            self.owner
                .padding_block
                .get_mut(length_start..block_bytes)
                .ok_or(Error::Failed)?
                .copy_from_slice(&total_bits.to_be_bytes());
        } else {
            self.owner
                .padding_block
                .get_mut(length_start..block_bytes)
                .ok_or(Error::Failed)?
                .copy_from_slice(
                    &u64::try_from(total_bits)
                        .map_err(|_| Error::MessageTooLong)?
                        .to_be_bytes(),
                );
        }
        self.padding(block_bytes)?;
        copy_prefix(
            &mut self.owner.output_staging,
            &self.owner.chaining_state,
            length,
        )?;
        *self
            .owner
            .output_staging
            .get_mut(length.checked_sub(1).ok_or(Error::Failed)?)
            .ok_or(Error::Failed)? &= mask;
        Ok(())
    }
    fn padding(&mut self, length: usize) -> Result<(), Error> {
        copy_prefix(
            &mut self.owner.block_copy,
            &self.owner.padding_block,
            length,
        )?;
        self.execution.compress(self.wide, &mut self.owner)?;
        self.report.padding_blocks = self
            .report
            .padding_blocks
            .checked_add(1)
            .ok_or(Error::MessageTooLong)?;
        Ok(())
    }
}

// Mutable update may be caught across unwind with the stream still alive.
fn copy_prefix(destination: &mut [u8], source: &[u8], length: usize) -> Result<(), Error> {
    destination
        .get_mut(..length)
        .ok_or(Error::Failed)?
        .copy_from_slice(source.get(..length).ok_or(Error::Failed)?);
    Ok(())
}

// A guard, not merely the stream's eventual Drop, therefore owns invalidation.
struct Update<'a> {
    owner: &'a mut HardenedSha2Owner,
    failed: &'a mut bool,
    completed: bool,
}
impl Drop for Update<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.wipe();
            *self.failed = true;
        }
    }
}

#[cfg(test)]
mod tests;
