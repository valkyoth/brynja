use super::{
    Algorithm, CAPACITY, Control, Digest, Error, Executor, Input, Mode, PublicData, Report,
};

pub(super) fn run(
    executor: &Executor<'_>,
    inputs: &[Option<Input<'_>>; CAPACITY],
    control: &mut Control<'_>,
) -> Result<([Option<Digest>; CAPACITY], Report), Error> {
    if let Some(session) = &executor.session {
        session.ensure_healthy().map_err(Error::Backend)?;
    }
    let mut indices = [0_usize; CAPACITY];
    let mut active = 0_usize;
    let mut states = [[0_u32; 8]; CAPACITY];
    for (index, (input, state)) in inputs.iter().zip(&mut states).enumerate() {
        if let Some(input) = input {
            u64::try_from(input.bits.bit_len()).map_err(|_| Error::MessageTooLong)?;
            *state = match input.algorithm {
                Algorithm::Sha224 => crate::sha224::INITIAL_STATE,
                Algorithm::Sha256 => crate::sha256::INITIAL_STATE,
            };
            *indices.get_mut(active).ok_or(Error::Invariant)? = index;
            active = active.checked_add(1).ok_or(Error::Invariant)?;
        }
    }
    let indices = indices.get(..active).ok_or(Error::Invariant)?;
    let mut offsets = [0_usize; CAPACITY];
    let mut report = Report::default();
    if let Some(session) = &executor.session {
        let width = session.kernel().width();
        for group in indices.chunks_exact(width) {
            let common = common_blocks(inputs, group)?;
            if common < executor.minimum_common_blocks {
                continue;
            }
            let mut packed = [[0_u32; 8]; CAPACITY];
            for (slot, index) in packed.iter_mut().zip(group) {
                *slot = *states.get(*index).ok_or(Error::Invariant)?;
            }
            for number in 0..common {
                let mut blocks = [[0_u8; 64]; CAPACITY];
                for (block, index) in blocks.iter_mut().zip(group) {
                    let input = inputs
                        .get(*index)
                        .and_then(Option::as_ref)
                        .ok_or(Error::Invariant)?;
                    *block = *input
                        .bits
                        .split()
                        .0
                        .as_chunks::<64>()
                        .0
                        .get(number)
                        .ok_or(Error::Invariant)?;
                }
                control.charge(u64::try_from(width).map_err(|_| Error::Invariant)?)?;
                let before = session.completed_vector_calls();
                // Classification follows the caller's PublicData batch: packed
                // IV/state and blocks derive only from its asserted-public input.
                // This preserves that assertion; it does not prove provenance.
                session
                    .compress(PublicData::new(&mut packed), PublicData::new(&blocks))
                    .map_err(Error::Backend)?;
                if session.completed_vector_calls()
                    != before.checked_add(1).ok_or(Error::Invariant)?
                {
                    return Err(Error::Invariant);
                }
                report.kernel = Some(session.kernel());
                report.vector_calls = checked_work(report.vector_calls, 1)?;
                report.vector_blocks = checked_work(
                    report.vector_blocks,
                    u64::try_from(width).map_err(|_| Error::Invariant)?,
                )?;
            }
            for (state, index) in packed.iter().zip(group) {
                *states.get_mut(*index).ok_or(Error::Invariant)? = *state;
                *offsets.get_mut(*index).ok_or(Error::Invariant)? = common;
            }
        }
    }
    if executor.mode == Mode::Require && report.vector_calls == 0 {
        return Err(Error::IneligibleWorkload);
    }
    let mut output = [None; CAPACITY];
    for (((input, state), offset), destination) in
        inputs.iter().zip(&mut states).zip(offsets).zip(&mut output)
    {
        if let Some(input) = input {
            finish(input, state, offset, control, &mut report)?;
            *destination = Some(render(input.algorithm, state));
        }
    }
    control.poll()?;
    if let Some(session) = &executor.session {
        session.ensure_healthy().map_err(Error::Backend)?;
    }
    Ok((output, report))
}

fn common_blocks(inputs: &[Option<Input<'_>>; CAPACITY], group: &[usize]) -> Result<usize, Error> {
    let mut common = usize::MAX;
    for index in group {
        let input = inputs
            .get(*index)
            .and_then(Option::as_ref)
            .ok_or(Error::Invariant)?;
        common = common.min(input.bits.split().0.len() / 64);
    }
    Ok(common)
}

fn scalar(
    state: &mut [u32; 8],
    block: &[u8; 64],
    control: &mut Control<'_>,
    report: &mut Report,
) -> Result<(), Error> {
    control.charge(1)?;
    crate::compress::compress(state, block);
    report.scalar_blocks = checked_work(report.scalar_blocks, 1)?;
    Ok(())
}

fn checked_work(total: u64, additional: u64) -> Result<u64, Error> {
    total.checked_add(additional).ok_or(Error::Invariant)
}

fn finish(
    input: &Input<'_>,
    state: &mut [u32; 8],
    offset: usize,
    control: &mut Control<'_>,
    report: &mut Report,
) -> Result<(), Error> {
    let (complete, tail) = input.bits.split();
    let (blocks, remainder) = complete.as_chunks::<64>();
    for block in blocks.get(offset..).ok_or(Error::Invariant)? {
        scalar(state, block, control, report)?;
    }
    let mut block = [0_u8; 64];
    for (out, byte) in block.iter_mut().zip(remainder) {
        *out = *byte;
    }
    let separator = match tail {
        Some((byte, valid)) => byte | (0x80_u8 >> valid),
        None => 0x80,
    };
    *block.get_mut(remainder.len()).ok_or(Error::Invariant)? = separator;
    if remainder.len() >= 56 {
        scalar(state, &block, control, report)?;
        block = [0; 64];
    }
    let length = u64::try_from(input.bits.bit_len()).map_err(|_| Error::MessageTooLong)?;
    block
        .get_mut(56..)
        .ok_or(Error::Invariant)?
        .copy_from_slice(&length.to_be_bytes());
    scalar(state, &block, control, report)
}

fn render(algorithm: Algorithm, state: &[u32; 8]) -> Digest {
    match algorithm {
        Algorithm::Sha224 => {
            let mut bytes = [0_u8; 28];
            for (out, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(state) {
                *out = word.to_be_bytes();
            }
            Digest::Sha224(crate::Sha224Digest::from_bytes(bytes))
        }
        Algorithm::Sha256 => {
            let mut bytes = [0_u8; 32];
            for (out, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(state) {
                *out = word.to_be_bytes();
            }
            Digest::Sha256(crate::Sha256Digest::from_bytes(bytes))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, checked_work};

    #[test]
    fn report_overflow_is_an_invariant_not_a_message_length_error() {
        assert_eq!(checked_work(0, 1), Ok(1));
        assert_eq!(checked_work(u64::MAX - 8, 8), Ok(u64::MAX));
        assert_eq!(checked_work(u64::MAX, 0), Ok(u64::MAX));
        assert_eq!(checked_work(u64::MAX, 1), Err(Error::Invariant));
        assert_eq!(checked_work(u64::MAX - 7, 8), Err(Error::Invariant));
    }

    #[test]
    fn scalar_report_overflow_rejects_without_wrapping() {
        let mut report = super::Report {
            scalar_blocks: u64::MAX,
            ..super::Report::default()
        };
        let mut cancel = || false;
        let mut control = super::Control::new(1, &mut cancel);
        let mut state = crate::sha256::INITIAL_STATE;
        assert_eq!(
            super::scalar(&mut state, &[0; 64], &mut control, &mut report),
            Err(Error::Invariant)
        );
        assert_eq!(report.scalar_blocks, u64::MAX);
        assert_eq!(control.used(), 1);
    }
}
