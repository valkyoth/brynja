use super::{Algorithm, CAPACITY, Control, Error, Executor, Input, Mode, Report, Workspace};

pub(super) fn run(
    executor: &Executor<'_>,
    inputs: &[Option<Input<'_>>; CAPACITY],
    s: &mut Workspace,
    control: &mut Control<'_>,
) -> Result<Report, Error> {
    s.wipe();
    let mut active = 0_usize;
    for (index, (input, state)) in inputs.iter().zip(&mut s.states).enumerate() {
        if let Some(input) = input {
            u64::try_from(input.bits.bit_len()).map_err(|_| Error::MessageTooLong)?;
            let initial = match input.algorithm {
                Algorithm::Sha224 => crate::sha224::INITIAL_STATE,
                Algorithm::Sha256 => crate::sha256::INITIAL_STATE,
            };
            for (out, word) in state.as_chunks_mut::<4>().0.iter_mut().zip(initial) {
                out.copy_from_slice(&word.to_be_bytes());
            }
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
                    let block = input
                        .bits
                        .split()
                        .0
                        .as_chunks::<64>()
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
        common = common.min(input.bits.split().0.len() / 64);
    }
    Ok(common)
}
fn work(total: u64, additional: u64) -> Result<u64, Error> {
    total.checked_add(additional).ok_or(Error::Invariant)
}

fn scalar(s: &mut Workspace, control: &mut Control<'_>, report: &mut Report) -> Result<(), Error> {
    control.charge(1)?;
    crate::hardened::compress32::compress(&mut s.scalar);
    s.scalar.wipe_compression_scratch();
    report.scalar_blocks = work(report.scalar_blocks, 1)?;
    Ok(())
}
fn padding(s: &mut Workspace, control: &mut Control<'_>, report: &mut Report) -> Result<(), Error> {
    transfer(
        s.scalar.block_copy.get_mut(..64).ok_or(Error::Invariant)?,
        s.scalar.padding_block.get(..64).ok_or(Error::Invariant)?,
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
        s.scalar
            .chaining_state
            .get_mut(..32)
            .ok_or(Error::Invariant)?,
        s.states.get(index).ok_or(Error::Invariant)?,
    )?;
    let offset = usize::try_from(u64::from_le_bytes(
        *s.offsets.get(index).ok_or(Error::Invariant)?,
    ))
    .map_err(|_| Error::Invariant)?;
    let (complete, tail) = input.bits.split();
    let (blocks, remainder) = complete.as_chunks::<64>();
    for block in blocks.get(offset..).ok_or(Error::Invariant)? {
        transfer(
            s.scalar.block_copy.get_mut(..64).ok_or(Error::Invariant)?,
            block,
        )?;
        scalar(s, control, report)?;
    }
    transfer(
        s.scalar
            .padding_block
            .get_mut(..remainder.len())
            .ok_or(Error::Invariant)?,
        remainder,
    )?;
    let separator = tail.map_or(0x80, |(byte, valid)| byte | (0x80_u8 >> valid));
    *s.scalar
        .padding_block
        .get_mut(remainder.len())
        .ok_or(Error::Invariant)? = separator;
    if remainder.len() >= 56 {
        padding(s, control, report)?;
        let _ = brynja_core::clear_owned_region(&mut s.scalar.padding_block);
    }
    let length = u64::try_from(input.bits.bit_len()).map_err(|_| Error::MessageTooLong)?;
    s.scalar
        .padding_block
        .get_mut(56..64)
        .ok_or(Error::Invariant)?
        .copy_from_slice(&length.to_be_bytes());
    padding(s, control, report)?;
    let width = input.algorithm.output_bytes();
    transfer(
        s.output
            .get_mut(index)
            .and_then(|slot| slot.get_mut(..width))
            .ok_or(Error::Invariant)?,
        s.scalar
            .chaining_state
            .get(..width)
            .ok_or(Error::Invariant)?,
    )?;
    s.scalar.wipe();
    Ok(())
}

fn transfer(destination: &mut [u8], source: &[u8]) -> Result<(), Error> {
    brynja_core::copy_secret_region(destination, source).map_err(|_| Error::Invariant)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn secret_transfer_mismatch_is_atomic_invariant_failure() {
        let mut output = [0xa5; 33];
        assert_eq!(transfer(&mut output, &[0x36; 32]), Err(Error::Invariant));
        assert_eq!(output, [0xa5; 33]);
        assert_eq!(transfer(&mut output[..32], &[0x36; 32]), Ok(()));
        assert_eq!(output[..32], [0x36; 32]);
        assert_eq!(output[32], 0xa5);
        assert_eq!(transfer(&mut [], &[]), Ok(()));
    }
    #[test]
    fn report_overflow_is_an_invariant_failure() {
        assert_eq!(work(u64::MAX, 0), Ok(u64::MAX));
        assert_eq!(work(u64::MAX, 1), Err(Error::Invariant));
        assert_eq!(work(0, u64::MAX), Ok(u64::MAX));
    }
}
