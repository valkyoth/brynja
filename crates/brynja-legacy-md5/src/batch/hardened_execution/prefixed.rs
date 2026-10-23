//! One borrowed prefix block per active lane; no concatenated message buffer.
use super::super::owner::BatchOwner;
use super::{Authority, BitString, Md5BatchControl, Md5BatchError, Md5BatchReport};
use crate::{
    cpu::{scratch::Scratch, transfer},
    engine,
};

pub(super) fn eligible(inputs: &[Option<BitString<'_>>; 8], width: usize) -> bool {
    // Only internal backend widths reach this helper. Fail closed on corruption.
    matches!(width, 4 | 8)
        && inputs
            .chunks(width)
            .any(|group| group.len() == width && group.iter().all(Option::is_some))
}

pub(super) fn absorb(
    owner: &mut BatchOwner,
    prefixes: &[[u8; 64]; 8],
    inputs: &[Option<BitString<'_>>; 8],
    control: &mut Md5BatchControl<'_>,
    authority: Option<&Authority>,
) -> Result<Md5BatchReport, Md5BatchError> {
    control.charge(0)?;
    let mut report = Md5BatchReport::default();
    let width = authority.map_or(8, |a| a.backend().lane_width());
    if !matches!(width, 4 | 8) {
        return Err(Md5BatchError::Backend);
    }
    for ((group, blocks), messages) in owner
        .lanes
        .chunks_mut(width)
        .zip(prefixes.chunks(width))
        .zip(inputs.chunks(width))
    {
        if let Some(authority) =
            authority.filter(|_| messages.len() == width && messages.iter().all(Option::is_some))
        {
            control.charge(width)?;
            let mut scratch = Scratch::new();
            for (slot, (lane, block)) in group.iter().zip(blocks).enumerate() {
                transfer::pack_state(&mut scratch, &lane.chaining_state, slot)
                    .map_err(|_| Md5BatchError::Backend)?;
                transfer::pack_block(&mut scratch, block, slot)
                    .map_err(|_| Md5BatchError::Backend)?;
            }
            authority
                .compress(&mut scratch)
                .map_err(|_| Md5BatchError::Backend)?;
            transfer::advance(&mut scratch);
            for (slot, lane) in group.iter_mut().enumerate() {
                transfer::commit_state(&scratch, &mut lane.chaining_state, slot)
                    .map_err(|_| Md5BatchError::Backend)?;
                lane.message_length = engine::admit_bytes(lane.bits(), 64)
                    .map_err(|_| Md5BatchError::MessageTooLong)?
                    .to_be_bytes();
            }
            report.vector_blocks = report
                .vector_blocks
                .checked_add(width)
                .ok_or(Md5BatchError::Backend)?;
        } else {
            for ((lane, block), input) in group.iter_mut().zip(blocks).zip(messages) {
                if input.is_some() {
                    control.charge(1)?;
                    engine::update(lane, block).map_err(|_| Md5BatchError::MessageTooLong)?;
                    report.scalar_blocks = report
                        .scalar_blocks
                        .checked_add(1)
                        .ok_or(Md5BatchError::Backend)?;
                }
            }
        }
    }
    Ok(report)
}
