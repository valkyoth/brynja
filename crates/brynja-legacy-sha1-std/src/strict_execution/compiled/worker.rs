use super::{Cancellation, Error, Sha1Backend};
use brynja_legacy_sha1::{
    BitString, Sha1BackendHealth,
    hardened_execution::{Executor, Mode, in_place},
};
pub(super) struct Request<'a> {
    pub backend: Sha1Backend,
    pub chunks: &'a [&'a [u8]],
    pub tail: &'a [u8],
    pub valid_bits: u8,
    pub cancel: &'a Cancellation,
    #[cfg(test)]
    pub fault: super::tests::Fault,
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Boundary {
    Setup,
    Update,
    Finalize,
    Output,
}
// Only called on protected stacks, including startup. No ordinary owner is imported.
pub(super) fn probe() -> Result<Sha1Backend, Error> {
    let executor = Executor::for_compiled_target(Mode::Require).map_err(Error::Execution)?;
    executor.report().backend.ok_or(Error::Invariant)
}
pub(super) fn run(request: Request<'_>, destination: &mut [u8]) -> Result<(), Error> {
    let Request {
        backend,
        chunks,
        tail,
        valid_bits,
        cancel,
        #[cfg(test)]
        fault,
    } = request;
    cancel.check()?;
    let tail = BitString::new(tail, valid_bits).map_err(|_| Error::InvalidBits)?;
    let (complete, partial) = tail.split_borrowed();
    let last = match partial {
        Some((byte, bits)) => BitString::new(core::slice::from_ref(byte), bits),
        None => BitString::new(&[], 0),
    }
    .map_err(|_| Error::InvalidBits)?;
    let executor = Executor::for_compiled_target(Mode::Require).map_err(Error::Execution)?;
    if executor.report().backend != Some(backend) {
        return Err(Error::Invariant);
    }
    let checkpoint = |point: Boundary| {
        let _ = point;
        #[cfg(test)]
        super::tests::inject(fault, point, &executor, cancel);
        if executor.report().health != Sha1BackendHealth::Healthy {
            return Err(Error::Quarantined);
        }
        cancel.check()
    };
    let mut scratch = [0u8; 20];
    let mut workspace = in_place::Sha1Workspace::new(&executor);
    #[cfg(test)]
    super::tests::observe(&scratch, destination, &executor, &workspace);
    workspace
        .with(|mut state| {
            checkpoint(Boundary::Setup)?;
            for chunk in chunks.iter().copied().chain(core::iter::once(complete)) {
                checkpoint(Boundary::Update)?;
                for part in chunk.chunks(4096) {
                    checkpoint(Boundary::Update)?;
                    state.update(part).map_err(Error::Execution)?;
                    checkpoint(Boundary::Update)?;
                }
            }
            checkpoint(Boundary::Finalize)?;
            let secret = state
                .finalize_bits_secret(last, &mut scratch)
                .map_err(Error::Execution)?;
            checkpoint(Boundary::Finalize)?;
            brynja_core::copy_secret_region(destination, secret.expose())
                .map_err(|_| Error::Invariant)?;
            checkpoint(Boundary::Output)
        })
        .map_err(Error::Execution)?
}
