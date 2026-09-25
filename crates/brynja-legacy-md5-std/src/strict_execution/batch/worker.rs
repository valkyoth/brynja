use super::{Cancellation, Error, Input, Md5Backend, api};
use brynja_legacy_md5::{BitString, Md5BackendHealth, Md5BatchControl};
pub(super) struct Request<'a> {
    pub inputs: &'a [Option<Input<'a>>; 8],
    pub max_compressions: usize,
    pub cancel: &'a Cancellation,
    pub backend: Md5Backend,
    #[cfg(test)]
    pub fault: super::tests::Fault,
}
pub(super) fn probe() -> Result<Md5Backend, Error> {
    let executor =
        api::Executor::for_compiled_target(api::Mode::Require).map_err(Error::Execution)?;
    executor.backend().ok_or(Error::Invariant)
}
pub(super) fn run(request: Request<'_>, destination: &mut [u8]) -> Result<api::Report, Error> {
    let Request {
        inputs,
        max_compressions,
        cancel,
        backend,
        #[cfg(test)]
        fault,
    } = request;
    cancel.check().map_err(|_| Error::Cancelled)?;
    let mut bits = [None; 8];
    for (slot, input) in bits.iter_mut().zip(inputs) {
        if let Some(input) = input {
            *slot = Some(
                BitString::new(input.bytes, input.valid_bits).map_err(|_| Error::InvalidBits)?,
            );
        }
    }
    let executor =
        api::Executor::for_compiled_target(api::Mode::Require).map_err(Error::Execution)?;
    if executor.backend() != Some(backend) {
        return Err(Error::Invariant);
    }
    let mut workspace = api::in_place::Workspace::new(&executor);
    let mut staging = [[0u8; 16]; 8];
    #[cfg(test)]
    super::tests::observe(&workspace, &executor, &staging, destination);
    #[cfg(test)]
    let mut checks = 0usize;
    let mut cancelled = || {
        #[cfg(test)]
        {
            super::tests::inject(fault, checks, &executor, cancel);
            checks = checks.saturating_add(1);
        }
        cancel.check().is_err()
    };
    let mut control = Md5BatchControl::with_cancellation(max_compressions, &mut cancelled);
    let (secret, report) = workspace
        .with(|batch| batch.digest_secret(&bits, &mut staging, &mut control))
        .map_err(Error::Execution)?
        .map_err(Error::Execution)?;
    if report.backend != Some(backend) || report.work.vector_blocks == 0 {
        return Err(Error::Invariant);
    }
    brynja_core::copy_secret_region(destination, secret.expose()).map_err(|_| Error::Invariant)?;
    #[cfg(test)]
    super::tests::inject(fault, usize::MAX, &executor, cancel);
    if executor.health() != Md5BackendHealth::Healthy {
        return Err(Error::Quarantined);
    }
    cancel.check().map_err(|_| Error::Cancelled)?;
    Ok(report)
}
