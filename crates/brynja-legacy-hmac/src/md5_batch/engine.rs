use super::{Input, Md5Batch, Md5BatchControl, Md5BatchReport, Md5Executor, Report};
use crate::{BitString, Error, scratch::mask};
use brynja_core::copy_secret_region;
use brynja_legacy_md5::{HardenedMd5Batch, Md5BatchError, hardened_execution as execution};
use execution::in_place::Workspace;

// Only empty arrays move into these owners; populated rows remain borrowed.
struct Rows<const N: usize>([[u8; N]; 8]);
impl<const N: usize> Rows<N> {
    fn new() -> Self {
        Self([[0; N]; 8])
    }
}
impl<const N: usize> Drop for Rows<N> {
    fn drop(&mut self) {
        let _ = brynja_core::clear_owned_region(self.0.as_flattened_mut());
    }
}

pub(super) struct Operation<'a> {
    executor: &'a Md5Executor,
    complete: bool,
}
impl<'a> Operation<'a> {
    pub(super) const fn new(executor: &'a Md5Executor) -> Self {
        Self {
            executor,
            complete: false,
        }
    }
    pub(super) fn complete<T>(&mut self, result: &Result<T, Error>) {
        self.complete = matches!(
            result,
            Ok(_)
                | Err(Error::WorkLimit
                    | Error::Cancelled
                    | Error::MessageTooLong
                    | Error::IneligibleWorkload)
        );
    }
}
impl Drop for Operation<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.executor.quarantine();
        }
    }
}

fn batch_error(error: Md5BatchError) -> Error {
    match error {
        Md5BatchError::WorkLimit => Error::WorkLimit,
        Md5BatchError::Cancelled => Error::Cancelled,
        Md5BatchError::MessageTooLong => Error::MessageTooLong,
        Md5BatchError::SecretMemory => Error::SecretMemory,
        _ => Error::ExecutionFailed,
    }
}
pub(super) fn execution_error(error: execution::Error) -> Error {
    match error {
        execution::Error::Batch(e) => batch_error(e),
        // After HMAC shape admission, a backend rejection is an integrity failure.
        execution::Error::IneligibleWorkload => Error::ExecutionFailed,
        _ => Error::ExecutionFailed,
    }
}

#[cfg(test)]
#[test]
fn post_admission_rejections_are_terminal() {
    assert_eq!(
        execution_error(execution::Error::IneligibleWorkload),
        Error::ExecutionFailed
    );
    for error in [
        Error::ExecutionFailed,
        Error::TagLength,
        Error::SecretMemory,
    ] {
        let executor = Md5Executor::portable();
        let mut guard = Operation::new(&executor);
        guard.complete(&Err::<(), _>(error));
        drop(guard);
        assert_eq!(
            executor.health(),
            brynja_legacy_md5::Md5BackendHealth::Quarantined
        );
    }
    for error in [
        Error::IneligibleWorkload,
        Error::Cancelled,
        Error::WorkLimit,
        Error::MessageTooLong,
    ] {
        let executor = Md5Executor::portable();
        let mut guard = Operation::new(&executor);
        guard.complete(&Err::<(), _>(error));
        drop(guard);
        assert_eq!(
            executor.health(),
            brynja_legacy_md5::Md5BackendHealth::Healthy
        );
    }
}

fn eligible<T>(inputs: &[Option<T>; 8], width: usize) -> bool {
    matches!(width, 4 | 8)
        && inputs
            .chunks(width)
            .any(|group| group.iter().all(Option::is_some))
}

fn checked_report(
    selection: &Md5Batch<'_>,
    report: execution::Report,
    active: usize,
) -> Result<Md5BatchReport, Error> {
    if report.backend != Some(selection.backend)
        || report.vector_width != selection.backend.lane_width()
        || report.work.vector_blocks < selection.backend.lane_width()
        || report.work.active_lanes != active
    {
        return Err(Error::ExecutionFailed);
    }
    Ok(report.work)
}

fn pads(
    selection: &Md5Batch<'_>,
    inputs: &[Option<Input<'_>>; 8],
    pads: &mut Rows<64>,
    workspace: &mut Workspace<'_>,
    control: &mut Md5BatchControl<'_>,
) -> Result<Md5BatchReport, Error> {
    let mut keys = [None; 8];
    for (slot, input) in keys.iter_mut().zip(inputs) {
        if let Some(input) = input
            && input.key.len() > 64
        {
            *slot = Some(BitString::new(input.key, 8).map_err(|_| Error::MessageTooLong)?);
        }
    }
    let mut normalized = Rows::<16>::new();
    let active = keys.iter().filter(|k| k.is_some()).count();
    let mut report = Md5BatchReport::default();
    let normalized = if active == 0 {
        None
    } else if eligible(&keys, selection.backend.lane_width()) {
        let (secret, actual) = workspace
            .with(|batch| batch.digest_secret(&keys, &mut normalized.0, control))
            .map_err(execution_error)?
            .map_err(execution_error)?;
        report = checked_report(selection, actual, active)?;
        Some(secret)
    } else {
        // Public key-shape choice BEFORE computation, never error-driven fallback.
        let (secret, actual) = HardenedMd5Batch::new()
            .digest_secret(&keys, &mut normalized.0, control)
            .map_err(batch_error)?;
        report = actual;
        Some(secret)
    };
    for (lane, (pad, input)) in pads.0.iter_mut().zip(inputs).enumerate() {
        if let Some(input) = input {
            let key = if input.key.len() > 64 {
                normalized
                    .as_ref()
                    .ok_or(Error::SecretMemory)?
                    .expose()
                    .as_chunks::<16>()
                    .0
                    .get(lane)
                    .ok_or(Error::SecretMemory)?
            } else {
                input.key
            };
            if !key.is_empty() {
                copy_secret_region(pad.get_mut(..key.len()).ok_or(Error::SecretMemory)?, key)?;
            }
            mask(pad, 0x36)?;
        }
    }
    Ok(report)
}

pub(super) fn compute<R>(
    selection: &Md5Batch<'_>,
    inputs: &[Option<Input<'_>>; 8],
    control: &mut Md5BatchControl<'_>,
    consume: impl FnOnce(&[u8]) -> Result<R, Error>,
) -> Result<(R, Report), Error> {
    let mut workspace = Workspace::new(selection.executor);
    // Revalidate even if the preselected token was retained across revocation.
    workspace
        .with(|batch| batch.cancel())
        .map_err(execution_error)?;
    if !eligible(inputs, selection.backend.lane_width()) {
        return Err(Error::IneligibleWorkload);
    }
    let active = inputs.iter().filter(|i| i.is_some()).count();
    let messages = inputs.each_ref().map(|i| i.as_ref().map(|i| i.message));
    let mut pad = Rows::<64>::new();
    let normalization = pads(selection, inputs, &mut pad, &mut workspace, control)?;
    let mut inner = Rows::<16>::new();
    let (inner_owner, actual) = workspace
        .with(|batch| batch.digest_prefixed_secret(&pad.0, &messages, &mut inner.0, control))
        .map_err(execution_error)?
        .map_err(execution_error)?;
    let inner = checked_report(selection, actual, active)?;
    let mut outer_inputs = [None; 8];
    for (((pad, input), outer), digest) in pad
        .0
        .iter_mut()
        .zip(inputs)
        .zip(&mut outer_inputs)
        .zip(inner_owner.expose().as_chunks::<16>().0)
    {
        if input.is_some() {
            mask(pad, 0x36 ^ 0x5c)?;
            *outer = Some(BitString::new(digest, 8).map_err(|_| Error::SecretMemory)?);
        }
    }
    let mut final_tags = Rows::<16>::new();
    let (tags, actual) = workspace
        .with(|batch| {
            batch.digest_prefixed_secret(&pad.0, &outer_inputs, &mut final_tags.0, control)
        })
        .map_err(execution_error)?
        .map_err(execution_error)?;
    let outer = checked_report(selection, actual, active)?;
    let mut truncated = Rows::<16>::new();
    for ((row, tag), input) in truncated
        .0
        .iter_mut()
        .zip(tags.expose().as_chunks::<16>().0)
        .zip(inputs)
    {
        if input.is_some() {
            copy_secret_region(
                row.get_mut(..selection.tag_bytes)
                    .ok_or(Error::SecretMemory)?,
                tag.get(..selection.tag_bytes).ok_or(Error::SecretMemory)?,
            )?;
        }
    }
    // No cancellation callback or secret computation follows this final check.
    workspace
        .with(|batch| batch.cancel())
        .map_err(execution_error)?;
    let result = consume(truncated.0.as_flattened())?;
    Ok((
        result,
        Report {
            backend: selection.backend,
            vector_width: selection.backend.lane_width(),
            normalization,
            inner,
            outer,
        },
    ))
}
