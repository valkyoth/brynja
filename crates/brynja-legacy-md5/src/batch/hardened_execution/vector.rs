//! Packs directly into clearing storage; never calls ordinary vector::execute.
use super::super::{
    Md5BatchControl, Md5BatchError, Md5BatchReport,
    owner::{BatchOwner, finish_lane},
};
use crate::{
    BitString,
    cpu::{scratch::Scratch, secret::Authority, transfer},
};

pub(super) fn execute(
    owner: &mut BatchOwner,
    inputs: &[Option<BitString<'_>>; 8],
    control: &mut Md5BatchControl<'_>,
    authority: &Authority,
) -> Result<Md5BatchReport, Md5BatchError> {
    authority
        .ensure_healthy()
        .map_err(|_| Md5BatchError::Backend)?;
    control.charge(0)?;
    let width = authority.backend().lane_width();
    let mut report = Md5BatchReport::default();
    for (group, messages) in owner.lanes.chunks_mut(width).zip(inputs.chunks(width)) {
        let blocks = messages
            .iter()
            .map(|i| i.map_or(0, |b| b.bit_len() / 512))
            .min()
            .unwrap_or(0);
        let mut scratch = Scratch::new();
        for (slot, lane) in group.iter().enumerate() {
            transfer::pack_state(&mut scratch, &lane.chaining_state, slot)
                .map_err(|_| Md5BatchError::Backend)?;
        }
        let mut prefix = 0_usize;
        for _ in 0..blocks {
            control.charge(width)?;
            let next = prefix
                .checked_add(64)
                .ok_or(Md5BatchError::MessageTooLong)?;
            for (slot, input) in messages.iter().enumerate() {
                let bytes = input
                    .ok_or(Md5BatchError::Backend)?
                    .as_bytes()
                    .get(prefix..next)
                    .ok_or(Md5BatchError::MessageTooLong)?;
                let block = bytes.try_into().map_err(|_| Md5BatchError::Backend)?;
                transfer::pack_block(&mut scratch, block, slot)
                    .map_err(|_| Md5BatchError::Backend)?;
            }
            authority
                .compress(&mut scratch)
                .map_err(|_| Md5BatchError::Backend)?;
            transfer::advance(&mut scratch);
            report.vector_blocks = report
                .vector_blocks
                .checked_add(width)
                .ok_or(Md5BatchError::WorkLimit)?;
            prefix = next;
        }
        for (slot, (lane, input)) in group.iter_mut().zip(messages).enumerate() {
            if let Some(input) = input {
                report.active_lanes = report
                    .active_lanes
                    .checked_add(1)
                    .ok_or(Md5BatchError::WorkLimit)?;
                if prefix != 0 {
                    transfer::commit_state(&scratch, &mut lane.chaining_state, slot)
                        .map_err(|_| Md5BatchError::Backend)?;
                    lane.message_length = crate::engine::admit_bytes(0, prefix)
                        .map_err(|_| Md5BatchError::MessageTooLong)?
                        .to_be_bytes();
                }
                finish_lane(lane, *input, prefix, control, &mut report)?;
            }
        }
    }
    control.charge(0)?;
    Ok(report)
}
