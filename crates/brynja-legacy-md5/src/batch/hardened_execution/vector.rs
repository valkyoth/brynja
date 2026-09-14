//! Packs directly into clearing storage; never calls ordinary vector::execute.
use super::super::{
    Md5BatchControl, Md5BatchError, Md5BatchReport,
    owner::{BatchOwner, finish_lane},
};
use crate::{
    BitString,
    cpu::{scratch::Scratch, secret::Authority},
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
            .map(|i| i.map_or(0, |b| b.split().0.len() / 64))
            .min()
            .unwrap_or(0);
        let mut scratch = Scratch::new();
        for (word, packed) in scratch.initial.iter_mut().enumerate() {
            for (dst, lane) in packed.as_chunks_mut::<4>().0.iter_mut().zip(group.iter()) {
                dst.copy_from_slice(
                    lane.chaining_state
                        .as_chunks::<4>()
                        .0
                        .get(word)
                        .ok_or(Md5BatchError::Backend)?,
                );
            }
        }
        let mut prefix = 0_usize;
        for _ in 0..blocks {
            control.charge(width)?;
            let next = prefix
                .checked_add(64)
                .ok_or(Md5BatchError::MessageTooLong)?;
            for (word, packed) in scratch.words.iter_mut().enumerate() {
                for (dst, input) in packed.as_chunks_mut::<4>().0.iter_mut().zip(messages) {
                    let bytes = input
                        .ok_or(Md5BatchError::Backend)?
                        .as_bytes()
                        .get(prefix..next)
                        .ok_or(Md5BatchError::MessageTooLong)?;
                    dst.copy_from_slice(
                        bytes
                            .as_chunks::<4>()
                            .0
                            .get(word)
                            .ok_or(Md5BatchError::Backend)?,
                    );
                }
            }
            authority
                .compress(&mut scratch)
                .map_err(|_| Md5BatchError::Backend)?;
            for (dst, src) in scratch.initial.iter_mut().zip(&scratch.work) {
                dst.copy_from_slice(src);
            }
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
                    for (dst, packed) in lane
                        .chaining_state
                        .as_chunks_mut::<4>()
                        .0
                        .iter_mut()
                        .zip(&scratch.initial)
                    {
                        dst.copy_from_slice(
                            packed
                                .as_chunks::<4>()
                                .0
                                .get(slot)
                                .ok_or(Md5BatchError::Backend)?,
                        );
                    }
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
