use super::{
    CAPACITY, Control, Error, Executor, Input, Mode, PublicData, Report, Workspace, framing::Cursor,
};

struct Lane<'a> {
    input: Input<'a>,
    cursor: Cursor<'a>,
    start: usize,
    written: usize,
    absorbing: bool,
    eligible: bool,
}

pub(super) fn run(
    executor: &Executor<'_>,
    inputs: &[Input<'_>],
    outputs: &mut [&mut [u8]],
    workspace: &mut Workspace,
    staging: &mut [u8],
    control: &mut Control<'_>,
) -> Result<Report, Error> {
    executor.check()?;
    if inputs.len() > CAPACITY || inputs.len() != outputs.len() {
        return Err(Error::InvalidInput);
    }
    let mut lanes: [Option<Lane<'_>>; CAPACITY] = core::array::from_fn(|_| None);
    let mut total = 0_usize;
    for ((slot, input), output) in lanes.iter_mut().zip(inputs).zip(outputs.iter()) {
        if output.len() != input.output_bytes() {
            return Err(Error::InvalidDestination);
        }
        let cursor = Cursor::new(*input)?;
        let eligible = cursor.permutations >= executor.minimum_permutations;
        *slot = Some(Lane {
            input: *input,
            cursor,
            start: total,
            written: 0,
            absorbing: true,
            eligible,
        });
        total = total
            .checked_add(input.output_bytes())
            .ok_or(Error::MessageTooLong)?;
    }
    if staging.len() < total {
        return Err(Error::InsufficientScratch);
    }
    let width = executor.session.as_ref().map(|s| s.kernel().width());
    if executor.mode == Mode::Require
        && width
            .is_none_or(|width| lanes.iter().flatten().filter(|lane| lane.eligible).count() < width)
    {
        return Err(Error::IneligibleWorkload);
    }
    control.poll()?;
    workspace.states.fill([0; 25]);
    let mut report = Report::default();
    loop {
        let mut ready = [false; CAPACITY];
        for ((lane, state), ready) in lanes.iter_mut().zip(&mut workspace.states).zip(&mut ready) {
            let Some(lane) = lane else {
                continue;
            };
            if lane.absorbing {
                lane.cursor
                    .absorb_block(state, lane.input.algorithm.rate())?;
                lane.absorbing = lane.cursor.remaining_blocks != 0;
                *ready = true;
            } else {
                lane.squeeze(state, staging)?;
                *ready = lane.written < lane.input.output_bytes();
            }
        }
        if !ready.iter().any(|r| *r) {
            break;
        }
        if let Some(width) = width {
            loop {
                let mut group = [0_usize; CAPACITY];
                let mut count = 0;
                for (i, (ready, lane)) in ready.iter().zip(&lanes).enumerate() {
                    if *ready && lane.as_ref().is_some_and(|lane| lane.eligible) {
                        *group.get_mut(count).ok_or(Error::Invariant)? = i;
                        count = count.checked_add(1).ok_or(Error::Invariant)?;
                        if count == width {
                            break;
                        }
                    }
                }
                if count == width {
                    vector(executor, workspace, &group, width, control, &mut report)?;
                    for index in group.iter().take(width) {
                        *ready.get_mut(*index).ok_or(Error::Invariant)? = false;
                    }
                } else {
                    break;
                }
            }
        }
        for (ready, state) in ready.into_iter().zip(&mut workspace.states) {
            if ready {
                control.charge(1)?;
                executor.check()?;
                crate::keccak::permute(state);
                report.scalar_permutations = report
                    .scalar_permutations
                    .checked_add(1)
                    .ok_or(Error::Invariant)?;
            }
        }
    }
    control.poll()?;
    executor.check()?;
    // Validate every source range before the first destination write. There are
    // no callbacks, backend calls, or fallible checks during the commit itself.
    let mut remainder = staging.get(..total).ok_or(Error::Invariant)?;
    for output in outputs.iter_mut() {
        let (source, rest) = remainder.split_at(output.len());
        output.copy_from_slice(source);
        remainder = rest;
    }
    Ok(report)
}

fn vector(
    executor: &Executor<'_>,
    workspace: &mut Workspace,
    group: &[usize; CAPACITY],
    width: usize,
    control: &mut Control<'_>,
    report: &mut Report,
) -> Result<(), Error> {
    let session = executor.session.as_ref().ok_or(Error::Invariant)?;
    let charge = u64::try_from(width).map_err(|_| Error::Invariant)?;
    control.charge(charge)?;
    workspace.vector.fill([0; 25]);
    for (target, index) in workspace.vector.iter_mut().zip(group).take(width) {
        *target = *workspace.states.get(*index).ok_or(Error::Invariant)?;
    }
    // Packed states come exclusively from the caller-classified Input values;
    // PublicData does not verify that assertion and cannot declassify secrets.
    session
        .permute(PublicData::new(&mut workspace.vector))
        .map_err(Error::Backend)?;
    for (state, index) in workspace.vector.iter().zip(group).take(width) {
        *workspace.states.get_mut(*index).ok_or(Error::Invariant)? = *state;
    }
    report.kernel = Some(session.kernel());
    report.vector_calls = report.vector_calls.checked_add(1).ok_or(Error::Invariant)?;
    report.vector_permutations = report
        .vector_permutations
        .checked_add(charge)
        .ok_or(Error::Invariant)?;
    Ok(())
}

impl Lane<'_> {
    fn squeeze(&mut self, state: &[u64; 25], staging: &mut [u8]) -> Result<(), Error> {
        let remaining = self
            .input
            .output_bytes()
            .checked_sub(self.written)
            .ok_or(Error::Invariant)?;
        let take = remaining.min(self.input.algorithm.rate());
        if take == 0 {
            return Ok(());
        }
        let start = self
            .start
            .checked_add(self.written)
            .ok_or(Error::Invariant)?;
        let end = start.checked_add(take).ok_or(Error::Invariant)?;
        let output = staging.get_mut(start..end).ok_or(Error::Invariant)?;
        for (position, target) in output.iter_mut().enumerate() {
            let word = state.get(position / 8).ok_or(Error::Invariant)?;
            *target = u8::try_from((word >> ((position % 8) << 3)) & 255)
                .map_err(|_| Error::Invariant)?;
        }
        self.written = self.written.checked_add(take).ok_or(Error::Invariant)?;
        if self.written == self.input.output_bytes() && !self.input.output_bits.is_multiple_of(8) {
            *output.last_mut().ok_or(Error::Invariant)? &=
                super::framing::mask(self.input.output_bits % 8);
        }
        Ok(())
    }
}
