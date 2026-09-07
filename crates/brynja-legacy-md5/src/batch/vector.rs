use super::{
    Md5BatchControl, Md5BatchError, Md5BatchReport,
    owner::{BatchOwner, finish_lane},
};
use crate::{BitString, Md5BackendSession};

pub(super) fn execute(
    owner: &mut BatchOwner,
    inputs: &[Option<BitString<'_>>; 8],
    control: &mut Md5BatchControl<'_>,
    session: &Md5BackendSession,
) -> Result<Md5BatchReport, Md5BatchError> {
    session
        .ensure_healthy()
        .map_err(|_| Md5BatchError::Backend)?;
    control.charge(0)?;
    let width = session.backend().lane_width();
    let mut report = Md5BatchReport::default();
    for (group, messages) in owner.lanes.chunks_mut(width).zip(inputs.chunks(width)) {
        // No lane compaction: an inactive slot prevents vectorization of that
        // group. Single-message and all uneven terminal work remain scalar.
        let blocks = messages
            .iter()
            .map(|input| input.map_or(0, |bits| bits.split().0.len() / 64))
            .min()
            .unwrap_or(0);
        let mut states = [[0_u32; 4]; 8];
        for (state, lane) in states.iter_mut().zip(group.iter()) {
            for (word, bytes) in state
                .iter_mut()
                .zip(lane.chaining_state.as_chunks::<4>().0.iter())
            {
                let [a, b, c, d] = bytes;
                *word = u32::from_le_bytes([*a, *b, *c, *d]);
            }
        }
        let mut prefix = 0_usize;
        for _ in 0..blocks {
            control.charge(width)?;
            let next = prefix
                .checked_add(64)
                .ok_or(Md5BatchError::MessageTooLong)?;
            let mut data = [[0_u8; 64]; 8];
            for (block, input) in data.iter_mut().zip(messages) {
                let bits = input.ok_or(Md5BatchError::Backend)?;
                let bytes = bits
                    .as_bytes()
                    .get(prefix..next)
                    .ok_or(Md5BatchError::MessageTooLong)?;
                block.copy_from_slice(bytes);
            }
            session
                .compress(&mut states, &data)
                .map_err(|_| Md5BatchError::Backend)?;
            report.vector_blocks = report
                .vector_blocks
                .checked_add(width)
                .ok_or(Md5BatchError::WorkLimit)?;
            prefix = next;
        }
        for ((lane, input), state) in group.iter_mut().zip(messages).zip(states) {
            if let Some(input) = input {
                report.active_lanes = report.active_lanes.saturating_add(1);
                if prefix != 0 {
                    for (bytes, word) in lane
                        .chaining_state
                        .as_chunks_mut::<4>()
                        .0
                        .iter_mut()
                        .zip(state)
                    {
                        bytes.copy_from_slice(&word.to_le_bytes());
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
