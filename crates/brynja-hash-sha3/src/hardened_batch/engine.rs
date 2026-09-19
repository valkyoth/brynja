use super::{
    CAPACITY, Control, Error, Executor, Input, Mode, Report, Workspace,
    framing::{mask, number, store},
};
pub(super) fn validate_commit(
    inputs: &[Option<Input<'_>>; CAPACITY],
    outputs: &[Option<&mut [u8]>; CAPACITY],
    staging: &[u8],
) -> Result<usize, Error> {
    super::output::validate(inputs, outputs)?;
    let mut total = 0_usize;
    for input in inputs.iter().flatten() {
        total = total
            .checked_add(input.output_bytes())
            .ok_or(Error::MessageTooLong)?;
    }
    if total > staging.len() {
        return Err(Error::InsufficientScratch);
    }
    Ok(total)
}
pub(super) fn run(
    executor: &Executor<'_>,
    inputs: &[Option<Input<'_>>; CAPACITY],
    s: &mut Workspace,
    staging: &mut [u8],
    control: &mut Control<'_>,
) -> Result<Report, Error> {
    s.wipe();
    let mut total = 0_usize;
    for (i, input) in inputs.iter().enumerate() {
        let Some(input) = input else {
            continue;
        };
        u64::try_from(input.output_bits()).map_err(|_| Error::MessageTooLong)?;
        let frame = s.frames.get_mut(i).ok_or(Error::Invariant)?;
        frame.initialize(input)?;
        *s.eligible.get_mut(i).ok_or(Error::Invariant)? =
            u8::from(frame.permutations()? >= executor.minimum_permutations);
        *s.absorbing.get_mut(i).ok_or(Error::Invariant)? = 1;
        store(s.starts.get_mut(i).ok_or(Error::Invariant)?, total)?;
        total = total
            .checked_add(input.output_bytes())
            .ok_or(Error::MessageTooLong)?;
    }
    if total > staging.len() {
        return Err(Error::InsufficientScratch);
    }
    let width = executor
        .session
        .as_ref()
        .map(|session| session.kernel().width());
    if executor.mode == Mode::Require
        && width.is_none_or(|width| s.eligible.iter().filter(|v| **v == 1).count() < width)
    {
        return Err(Error::IneligibleWorkload);
    }
    control.poll()?;
    let mut report = Report::default();
    loop {
        s.ready.fill(0);
        for (i, input) in inputs.iter().enumerate() {
            let Some(input) = input else {
                continue;
            };
            if *s.absorbing.get(i).ok_or(Error::Invariant)? == 1 {
                let frame = s.frames.get_mut(i).ok_or(Error::Invariant)?;
                frame.absorb(input, s.states.get_mut(i).ok_or(Error::Invariant)?)?;
                *s.absorbing.get_mut(i).ok_or(Error::Invariant)? =
                    u8::from(frame.remaining()? != 0);
                *s.ready.get_mut(i).ok_or(Error::Invariant)? = 1;
            } else {
                squeeze(input, i, s, staging)?;
                *s.ready.get_mut(i).ok_or(Error::Invariant)? = u8::from(
                    number(s.written.get(i).ok_or(Error::Invariant)?)? < input.output_bytes(),
                );
            }
        }
        if s.ready.iter().all(|v| *v == 0) {
            break;
        }
        if let Some(width) = width {
            // Only public slot indices live in this local grouping array.
            loop {
                let mut group = [0_usize; CAPACITY];
                let mut count = 0_usize;
                for (i, (ready, eligible)) in s.ready.iter().zip(&s.eligible).enumerate() {
                    if *ready == 1 && *eligible == 1 {
                        *group.get_mut(count).ok_or(Error::Invariant)? = i;
                        count = count.checked_add(1).ok_or(Error::Invariant)?;
                        if count == width {
                            break;
                        }
                    }
                }
                if count != width {
                    break;
                }
                vector(executor, s, &group, width, control, &mut report)?;
                for index in group.iter().take(width) {
                    *s.ready.get_mut(*index).ok_or(Error::Invariant)? = 0;
                }
            }
        }
        for (ready, state) in s.ready.iter().zip(&mut s.states) {
            if *ready == 1 {
                control.charge(1)?;
                executor.check()?;
                transfer(&mut s.scalar.sponge_lanes, state)?;
                crate::hardened::permutation::permute(&mut s.scalar);
                transfer(state, &s.scalar.sponge_lanes)?;
                s.scalar.wipe();
                report.scalar_permutations = report
                    .scalar_permutations
                    .checked_add(1)
                    .ok_or(Error::Invariant)?;
            }
        }
    }
    control.poll()?;
    executor.check()?;
    Ok(report)
}
fn vector(
    executor: &Executor<'_>,
    s: &mut Workspace,
    group: &[usize; CAPACITY],
    width: usize,
    control: &mut Control<'_>,
    report: &mut Report,
) -> Result<(), Error> {
    let session = executor.session.as_ref().ok_or(Error::Invariant)?;
    let charge = u64::try_from(width).map_err(|_| Error::Invariant)?;
    control.charge(charge)?;
    // Clear even unused packed capacity before gathering secret byte states.
    let _ = brynja_core::clear_owned_region(s.vector.as_flattened_mut());
    for (out, index) in s.vector.iter_mut().zip(group).take(width) {
        transfer(out, s.states.get(*index).ok_or(Error::Invariant)?)?;
    }
    let before = session.completed_vector_calls();
    session
        .permute_bytes(&mut s.vector, &mut s.cpu)
        .map_err(Error::Backend)?;
    if session.completed_vector_calls() != before.checked_add(1).ok_or(Error::Invariant)? {
        return Err(Error::Invariant);
    }
    for (state, index) in s.vector.iter().zip(group).take(width) {
        transfer(s.states.get_mut(*index).ok_or(Error::Invariant)?, state)?;
        report.accelerated_slots |= 1_u8
            .checked_shl(u32::try_from(*index).map_err(|_| Error::Invariant)?)
            .ok_or(Error::Invariant)?;
    }
    report.kernel = Some(session.kernel());
    report.vector_calls = report.vector_calls.checked_add(1).ok_or(Error::Invariant)?;
    report.vector_permutations = report
        .vector_permutations
        .checked_add(charge)
        .ok_or(Error::Invariant)?;
    Ok(())
}
fn squeeze(
    input: &Input<'_>,
    i: usize,
    s: &mut Workspace,
    staging: &mut [u8],
) -> Result<(), Error> {
    let written = number(s.written.get(i).ok_or(Error::Invariant)?)?;
    let remaining = input
        .output_bytes()
        .checked_sub(written)
        .ok_or(Error::Invariant)?;
    let take = remaining.min(input.algorithm.rate());
    if take == 0 {
        return Ok(());
    }
    let start = number(s.starts.get(i).ok_or(Error::Invariant)?)?
        .checked_add(written)
        .ok_or(Error::Invariant)?;
    let end = start.checked_add(take).ok_or(Error::Invariant)?;
    let out = staging.get_mut(start..end).ok_or(Error::Invariant)?;
    transfer(
        out,
        s.states
            .get(i)
            .and_then(|v| v.get(..take))
            .ok_or(Error::Invariant)?,
    )?;
    let written = written.checked_add(take).ok_or(Error::Invariant)?;
    store(s.written.get_mut(i).ok_or(Error::Invariant)?, written)?;
    if written == input.output_bytes() && !input.output_bits().is_multiple_of(8) {
        brynja_core::apply_secret_byte_mask(
            out.last_mut().ok_or(Error::Invariant)?,
            mask(input.output_bits() % 8),
            0,
        );
    }
    Ok(())
}
fn transfer(destination: &mut [u8], source: &[u8]) -> Result<(), Error> {
    brynja_core::copy_secret_region(destination, source).map_err(|_| Error::Invariant)
}

#[cfg(test)]
mod tests {
    #[test]
    fn transfer_rejects_mismatched_lengths_without_mutation() {
        let mut destination = [0xa5; 200];
        assert_eq!(
            super::transfer(&mut destination, &[0; 199]),
            Err(super::Error::Invariant)
        );
        assert_eq!(destination, [0xa5; 200]);
        assert_eq!(super::transfer(&mut [], &[]), Ok(()));
    }
}
