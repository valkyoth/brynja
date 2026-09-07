use super::{Md5BatchControl, Md5BatchError, Md5BatchReport};
use crate::{BitString, engine, owner::Md5Owner};

// No new secret-bearing representation: all regions remain in the registered
// Md5Owner. Array destruction invokes all eight non-panicking clearing Drops.
pub(super) struct BatchOwner {
    pub(super) lanes: [Md5Owner; 8],
}
impl BatchOwner {
    pub(super) fn new() -> Self {
        Self {
            lanes: core::array::from_fn(|_| Md5Owner::new()),
        }
    }
    pub(super) fn portable(
        &mut self,
        inputs: &[Option<BitString<'_>>; 8],
        control: &mut Md5BatchControl<'_>,
    ) -> Result<Md5BatchReport, Md5BatchError> {
        let mut report = Md5BatchReport::default();
        control.charge(0)?;
        for (lane, input) in self.lanes.iter_mut().zip(inputs) {
            if let Some(input) = input {
                report.active_lanes = report.active_lanes.saturating_add(1);
                finish_lane(lane, *input, 0, control, &mut report)?;
            }
        }
        control.charge(0)?;
        Ok(report)
    }
    pub(super) fn commit_public(&self, output: &mut [[u8; 16]; 8]) {
        for (destination, lane) in output.iter_mut().zip(&self.lanes) {
            destination.copy_from_slice(&lane.output_staging);
        }
    }
}

pub(super) fn finish_lane(
    owner: &mut Md5Owner,
    input: BitString<'_>,
    prefix: usize,
    control: &mut Md5BatchControl<'_>,
    report: &mut Md5BatchReport,
) -> Result<(), Md5BatchError> {
    let (bytes, partial) = input.split();
    let suffix = bytes.get(prefix..).ok_or(Md5BatchError::MessageTooLong)?;
    for chunk in suffix.chunks(64) {
        if chunk.len() == 64 {
            control.charge(1)?;
            report.scalar_blocks = report
                .scalar_blocks
                .checked_add(1)
                .ok_or(Md5BatchError::WorkLimit)?;
        } else {
            control.charge(0)?;
        }
        engine::update(owner, chunk).map_err(|_| Md5BatchError::MessageTooLong)?;
    }
    let padding = if owner.buffered() >= 56 { 2 } else { 1 };
    control.charge(padding)?;
    report.scalar_blocks = report
        .scalar_blocks
        .checked_add(padding)
        .ok_or(Md5BatchError::WorkLimit)?;
    let tail = match partial {
        Some((_byte, valid)) => BitString::new(
            input
                .as_bytes()
                .get(bytes.len()..)
                .ok_or(Md5BatchError::MessageTooLong)?,
            valid,
        ),
        None => BitString::new(&[], 0),
    }
    .map_err(|_| Md5BatchError::MessageTooLong)?;
    engine::finish(owner, tail).map_err(|_| Md5BatchError::MessageTooLong)
}
