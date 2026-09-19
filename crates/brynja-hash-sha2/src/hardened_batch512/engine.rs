use super::{Algorithm, CAPACITY, Control, Error, Executor, Input, Mode, Report, Workspace};

pub(super) fn run(
    executor: &Executor<'_>,
    inputs: &[Option<Input<'_>>; CAPACITY],
    s: &mut Workspace,
    control: &mut Control<'_>,
) -> Result<Report, Error> {
    s.wipe();
    let mut active = 0_usize;
    for (index, input) in inputs.iter().enumerate() {
        if let Some(input) = input {
            u128::try_from(input.bits.bit_len()).map_err(|_| Error::MessageTooLong)?;
            *s.indices.get_mut(active).ok_or(Error::Invariant)? =
                u8::try_from(index).map_err(|_| Error::Invariant)?;
            active = active.checked_add(1).ok_or(Error::Invariant)?;
        }
    }
    s.active = [u8::try_from(active).map_err(|_| Error::Invariant)?];
    let width = executor
        .session
        .as_ref()
        .map_or(CAPACITY, |session| session.kernel().width());
    if executor.mode == Mode::Require {
        let mut eligible = false;
        for group in (0..active).step_by(width) {
            if active.saturating_sub(group) >= width
                && common(inputs, s, group, width)? >= executor.minimum_common_blocks
            {
                eligible = true;
            }
        }
        if !eligible {
            return Err(Error::IneligibleWorkload);
        }
    }
    control.poll()?;
    let mut report = Report::default();
    for (input, state) in inputs.iter().zip(&mut s.states) {
        if let Some(input) = input {
            // IVs depend only on public identity/t, never secret message bytes.
            if matches!(input.algorithm, Algorithm::Sha512T(_)) {
                control.charge(1)?;
                report.scalar_blocks = work(report.scalar_blocks, 1)?;
            }
            for (out, word) in state
                .as_chunks_mut::<8>()
                .0
                .iter_mut()
                .zip(input.algorithm.initial_words())
            {
                out.copy_from_slice(&word.to_be_bytes());
            }
        }
    }
    if let Some(session) = &executor.session {
        for group in (0..active).step_by(width) {
            if active.saturating_sub(group) < width {
                break;
            }
            let common = common(inputs, s, group, width)?;
            if common < executor.minimum_common_blocks {
                continue;
            }
            for lane in 0..width {
                let index = s.index(group, lane)?;
                transfer(
                    s.packed.get_mut(lane).ok_or(Error::Invariant)?,
                    s.states.get(index).ok_or(Error::Invariant)?,
                )?;
            }
            for number in 0..common {
                for lane in 0..width {
                    let index = s.index(group, lane)?;
                    let input = inputs
                        .get(index)
                        .and_then(Option::as_ref)
                        .ok_or(Error::Invariant)?;
                    let block = complete_bytes(input.bits)?
                        .as_chunks::<128>()
                        .0
                        .get(number)
                        .ok_or(Error::Invariant)?;
                    transfer(s.blocks.get_mut(lane).ok_or(Error::Invariant)?, block)?;
                }
                control.charge(u64::try_from(width).map_err(|_| Error::Invariant)?)?;
                let before = session.completed_vector_calls();
                session
                    .compress_bytes(&mut s.packed, &s.blocks, &mut s.cpu)
                    .map_err(Error::Backend)?;
                if session.completed_vector_calls()
                    != before.checked_add(1).ok_or(Error::Invariant)?
                {
                    return Err(Error::Invariant);
                }
                report.kernel = Some(session.kernel());
                report.vector_calls = work(report.vector_calls, 1)?;
                report.vector_blocks = work(
                    report.vector_blocks,
                    u64::try_from(width).map_err(|_| Error::Invariant)?,
                )?;
            }
            for lane in 0..width {
                let index = s.index(group, lane)?;
                transfer(
                    s.states.get_mut(index).ok_or(Error::Invariant)?,
                    s.packed.get(lane).ok_or(Error::Invariant)?,
                )?;
                s.offsets
                    .get_mut(index)
                    .ok_or(Error::Invariant)?
                    .copy_from_slice(
                        &u64::try_from(common)
                            .map_err(|_| Error::Invariant)?
                            .to_le_bytes(),
                    );
            }
        }
    }
    for (index, input) in inputs.iter().enumerate() {
        if let Some(input) = input {
            finish(input, index, s, control, &mut report)?;
        }
    }
    control.poll()?;
    executor.check()?;
    Ok(report)
}
fn common(
    inputs: &[Option<Input<'_>>; CAPACITY],
    s: &Workspace,
    group: usize,
    width: usize,
) -> Result<usize, Error> {
    let mut common = usize::MAX;
    for lane in 0..width {
        let input = inputs
            .get(s.index(group, lane)?)
            .and_then(Option::as_ref)
            .ok_or(Error::Invariant)?;
        common = common.min(complete_bytes(input.bits)?.len() / 128);
    }
    Ok(common)
}
fn work(total: u64, additional: u64) -> Result<u64, Error> {
    total.checked_add(additional).ok_or(Error::Invariant)
}

fn transfer(destination: &mut [u8], source: &[u8]) -> Result<(), Error> {
    brynja_core::copy_secret_region(destination, source).map_err(|_| Error::Invariant)
}

fn scalar(s: &mut Workspace, control: &mut Control<'_>, report: &mut Report) -> Result<(), Error> {
    control.charge(1)?;
    crate::hardened::compress64::compress(&mut s.scalar);
    s.scalar.wipe_compression_scratch();
    report.scalar_blocks = work(report.scalar_blocks, 1)?;
    Ok(())
}
fn padding(s: &mut Workspace, control: &mut Control<'_>, report: &mut Report) -> Result<(), Error> {
    transfer(
        &mut s.scalar.block_copy,
        s.scalar.padding_block.get(..128).ok_or(Error::Invariant)?,
    )?;
    scalar(s, control, report)
}
fn finish(
    input: &Input<'_>,
    index: usize,
    s: &mut Workspace,
    control: &mut Control<'_>,
    report: &mut Report,
) -> Result<(), Error> {
    s.scalar.wipe();
    transfer(
        &mut s.scalar.chaining_state,
        s.states.get(index).ok_or(Error::Invariant)?,
    )?;
    let offset = usize::try_from(u64::from_le_bytes(
        *s.offsets.get(index).ok_or(Error::Invariant)?,
    ))
    .map_err(|_| Error::Invariant)?;
    let complete = complete_bytes(input.bits)?;
    let (blocks, remainder) = complete.as_chunks::<128>();
    for block in blocks.get(offset..).ok_or(Error::Invariant)? {
        transfer(&mut s.scalar.block_copy, block)?;
        scalar(s, control, report)?;
    }
    transfer(
        s.scalar
            .padding_block
            .get_mut(..remainder.len())
            .ok_or(Error::Invariant)?,
        remainder,
    )?;
    let separator = s
        .scalar
        .padding_block
        .get_mut(remainder.len())
        .ok_or(Error::Invariant)?;
    if input.bits.is_byte_aligned() {
        *separator = 0x80;
    } else {
        transfer(
            core::slice::from_mut(separator),
            core::slice::from_ref(input.bits.as_bytes().last().ok_or(Error::Invariant)?),
        )?;
        brynja_core::apply_secret_byte_mask(
            separator,
            0xff,
            0x80_u8 >> input.bits.valid_bits_in_last_byte(),
        );
    }
    if remainder.len() >= 112 {
        padding(s, control, report)?;
        let _ = brynja_core::clear_owned_region(&mut s.scalar.padding_block);
    }
    let length = u128::try_from(input.bits.bit_len()).map_err(|_| Error::MessageTooLong)?;
    s.scalar
        .padding_block
        .get_mut(112..128)
        .ok_or(Error::Invariant)?
        .copy_from_slice(&length.to_be_bytes());
    padding(s, control, report)?;
    let width = input.algorithm.output_bytes();
    transfer(
        s.output
            .get_mut(index)
            .and_then(|out| out.get_mut(..width))
            .ok_or(Error::Invariant)?,
        s.scalar
            .chaining_state
            .get(..width)
            .ok_or(Error::Invariant)?,
    )?;
    let last = input
        .algorithm
        .output_bytes()
        .checked_sub(1)
        .ok_or(Error::Invariant)?;
    let last_byte = s
        .output
        .get_mut(index)
        .and_then(|out| out.get_mut(last))
        .ok_or(Error::Invariant)?;
    brynja_core::apply_secret_byte_mask(last_byte, input.algorithm.last_byte_mask(), 0);
    s.scalar.wipe();
    Ok(())
}

fn complete_bytes(bits: super::BitString<'_>) -> Result<&[u8], Error> {
    // Unlike split(), this never materializes the secret partial byte in Rust.
    bits.as_bytes()
        .get(..bits.bit_len() / 8)
        .ok_or(Error::Invariant)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn secret_transfer_mismatch_is_atomic_invariant_failure() {
        let source = [0x63; 64];
        let mut destination = [0xa5; 65];
        assert_eq!(transfer(&mut destination, &source), Err(Error::Invariant));
        assert_eq!(destination, [0xa5; 65]);
        assert_eq!(source, [0x63; 64]);
    }
    #[test]
    fn report_overflow_is_an_invariant_failure() {
        assert_eq!(work(u64::MAX, 0), Ok(u64::MAX));
        assert_eq!(work(u64::MAX, 1), Err(Error::Invariant));
        assert_eq!(work(0, u64::MAX), Ok(u64::MAX));
    }
}
