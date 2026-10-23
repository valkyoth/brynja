use super::{Cancellation, Error, LegacyUse, Md5Backend, Md5BatchInput};
use brynja_legacy_hmac::{
    BitString,
    md5_batch::{Input, Md5Batch, Md5BatchControl, Md5Executor, Md5Mode, Report},
};

pub(super) struct Parameters {
    pub backend: Md5Backend,
    pub bytes: usize,
    pub budget: usize,
}
pub(super) fn probe() -> Result<Md5Backend, Error> {
    let owner = Md5Executor::for_compiled_target(Md5Mode::Require)
        .map_err(|_| Error::Mac(brynja_legacy_hmac::Error::ExecutionUnavailable))?;
    owner.backend().ok_or(Error::Invariant)
}
fn healthy(owner: &Md5Executor) -> Result<(), Error> {
    // Selection performs real authority revalidation before any key is accepted;
    // use it again even on rejection, so a revoked owner cannot look reusable.
    let _ = Md5Batch::new(LegacyUse::acknowledge(), owner).map_err(Error::Mac)?;
    Ok(())
}
fn checkpoint(owner: &Md5Executor, cancel: &Cancellation) -> Result<(), Error> {
    #[cfg(test)]
    super::tests::checkpoint(owner, cancel);
    healthy(owner)?;
    cancel.check()
}
fn report(report: Report, parameters: &Parameters, active: usize) -> Result<(), Error> {
    #[cfg(test)]
    let report = super::tests::report(report);
    if report.backend != parameters.backend
        || report.vector_width != parameters.backend.lane_width()
        || report.inner.active_lanes != active
        || report.outer.active_lanes != active
        || report.inner.vector_blocks < parameters.backend.lane_width()
        || report.outer.vector_blocks < parameters.backend.lane_width()
    {
        return Err(Error::Invariant);
    }
    Ok(())
}
pub(super) fn run(
    parameters: Parameters,
    inputs: &[Option<Md5BatchInput<'_>>; 8],
    candidates: Option<&[Option<&[u8]>; 8]>,
    cancel: &Cancellation,
    staging: &mut [u8],
    output: &mut [u8],
) -> Result<Option<bool>, Error> {
    if staging.len() != 128 || output.len() != 128 {
        return Err(Error::Invariant);
    }
    let owner = Md5Executor::for_compiled_target(Md5Mode::Require)
        .map_err(|_| Error::Mac(brynja_legacy_hmac::Error::ExecutionFailed))?;
    if owner.backend() != Some(parameters.backend) {
        return Err(Error::Invariant);
    }
    checkpoint(&owner, cancel)?;
    let mut lanes = [const { None }; 8];
    for (lane, input) in lanes.iter_mut().zip(inputs) {
        if let Some(input) = input {
            *lane = Some(Input::new(
                input.key,
                BitString::new(input.message.bytes, input.message.valid_bits)
                    .map_err(|_| Error::InvalidBits)?,
            ));
        }
    }
    let selection = Md5Batch::with_tag_length(LegacyUse::acknowledge(), &owner, parameters.bytes)
        .map_err(Error::Mac)?;
    #[cfg(test)]
    super::tests::observe(&selection, staging, output);
    let mut cancelled = || {
        #[cfg(test)]
        super::tests::checkpoint(&owner, cancel);
        cancel.check().is_err()
    };
    let mut control = Md5BatchControl::with_cancellation(parameters.budget, &mut cancelled);
    let active = inputs.iter().filter(|v| v.is_some()).count();
    let result = if let Some(candidates) = candidates {
        let result = selection
            .verify(&lanes, candidates, &mut control)
            .map_err(Error::Mac);
        healthy(&owner)?;
        let (decision, actual) = result?;
        report(actual, &parameters, active)?;
        Some(decision.expose_public())
    } else {
        let (rows, remainder) = staging.as_chunks_mut::<16>();
        if !remainder.is_empty() {
            return Err(Error::Invariant);
        }
        let rows: &mut [[u8; 16]; 8] = rows.try_into().map_err(|_| Error::Invariant)?;
        let result = selection
            .authenticate_secret(&lanes, rows, &mut control)
            .map_err(Error::Mac);
        healthy(&owner)?;
        let (tags, actual) = result?;
        report(actual, &parameters, active)?;
        checkpoint(&owner, cancel)?;
        for (lane, row) in output.as_chunks_mut::<16>().0.iter_mut().enumerate() {
            if let Some(tag) = tags.expose(lane) {
                let destination = row.get_mut(..parameters.bytes).ok_or(Error::Invariant)?;
                brynja_core::copy_secret_region(destination, tag).map_err(|_| Error::Invariant)?;
            }
        }
        #[cfg(test)]
        super::tests::after_write(&owner, cancel);
        None
    };
    checkpoint(&owner, cancel)?;
    Ok(result)
}
